#Requires -Version 5.1
<#
.SYNOPSIS
    RC4 Deprecation Readiness Audit - Full Forest Scan

.DESCRIPTION
    Audits all domains in an Active Directory forest for RC4 encryption
    exposure across user accounts, computer accounts, service accounts,
    gMSAs, KDC event logs, SPNs, and Group Policy Kerberos settings.

    Produces a set of CSV files and a unified master CSV suitable for
    loading into the RC4 Deprecation Readiness Dashboard (HTML).

    Author  : Darren Reevell, Senior Platform Engineer
              Intertek Group plc - Platform Engineering
    Version : 1.1
    Updated : April 2026

    Run as Domain Admin or with delegated read rights across all domains.
    Requires: ActiveDirectory and GroupPolicy PowerShell modules (RSAT).

.PARAMETER OutputPath
    Folder where CSV output files will be written. Default: C:\RC4_Audit\

.PARAMETER ForestRootDomain
    FQDN of the forest root domain. Child domains are auto-discovered.

.PARAMETER SkipEventLog
    Switch - include to skip KDC Security event log collection.
    Use if PDC Emulators block remote event log access or if Zscaler
    intercepts the WinRM connection.

.PARAMETER EventLogHours
    How many hours back to search the KDC Security event log. Default: 72.

.EXAMPLE
    .\Invoke-RC4Audit.ps1 -ForestRootDomain "corp.internal" -OutputPath "C:\RC4_Audit"

.EXAMPLE
    .\Invoke-RC4Audit.ps1 -ForestRootDomain "corp.internal" -SkipEventLog

.EXAMPLE
    .\Invoke-RC4Audit.ps1 -ForestRootDomain "corp.internal" -EventLogHours 168

.NOTES
    This script is read-only. It makes no changes to Active Directory.
    Save as UTF-8 (ASCII-safe version - no Unicode characters used).
    Output CSVs are UTF-8 with BOM for compatibility with Excel and
    the RC4 Dashboard HTML file.
#>

[CmdletBinding()]
param(
    [string]$OutputPath       = "C:\RC4_Audit",
    [string]$ForestRootDomain = "corp.internal",
    [switch]$SkipEventLog,
    [int]$EventLogHours       = 72
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Continue"

# ---------------------------------------------------------------------------
# Encryption type bitmask reference
# Bit 0 (1)   = DES-CBC-CRC
# Bit 1 (2)   = DES-CBC-MD5
# Bit 2 (4)   = RC4-HMAC (RC4)
# Bit 3 (8)   = AES128-CTS-HMAC-SHA1-96
# Bit 4 (16)  = AES256-CTS-HMAC-SHA1-96
# 0 or null   = inherits domain default (2012 FL default includes RC4)
# ---------------------------------------------------------------------------

function Get-EncryptionTypes {
    param([int]$Mask)
    $types = @()
    if ($Mask -band 1)  { $types += "DES-CRC" }
    if ($Mask -band 2)  { $types += "DES-MD5" }
    if ($Mask -band 4)  { $types += "RC4-HMAC" }
    if ($Mask -band 8)  { $types += "AES128" }
    if ($Mask -band 16) { $types += "AES256" }
    if ($types.Count -eq 0) { return "Inherits-Default(includes-RC4)" }
    return ($types -join "|")
}

function Test-RC4Enabled {
    param([int]$Mask)
    # 0 = not explicitly set; domain default on 2012 FL allows RC4
    if ($Mask -eq 0) { return $true }
    return [bool]($Mask -band 4)
}

function Test-AES256Only {
    param([int]$Mask)
    if ($Mask -eq 0) { return $false }
    return (($Mask -band 16) -and (-not ($Mask -band 4)) -and (-not ($Mask -band 3)))
}

# ---------------------------------------------------------------------------
# Initialise output folder
# ---------------------------------------------------------------------------
if (-not (Test-Path $OutputPath)) {
    New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
}

$Timestamp      = Get-Date -Format "yyyyMMdd_HHmmss"
$AccountsCSV    = Join-Path $OutputPath "RC4_Accounts_$Timestamp.csv"
$EventLogCSV    = Join-Path $OutputPath "RC4_EventLog_$Timestamp.csv"
$GPOSettingsCSV = Join-Path $OutputPath "RC4_GPO_$Timestamp.csv"
$SummaryCSV     = Join-Path $OutputPath "RC4_Summary_$Timestamp.csv"
$MasterCSV      = Join-Path $OutputPath "RC4_Master_$Timestamp.csv"

Write-Host ""
Write-Host "=================================================" -ForegroundColor Cyan
Write-Host "   RC4 DEPRECATION READINESS AUDIT" -ForegroundColor Cyan
Write-Host "=================================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Forest Root : $ForestRootDomain"
Write-Host "Output Path : $OutputPath"
Write-Host "Started     : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
Write-Host ""

# ---------------------------------------------------------------------------
# Import ActiveDirectory module
# ---------------------------------------------------------------------------
try {
    Import-Module ActiveDirectory -ErrorAction Stop
} catch {
    Write-Error "ActiveDirectory module not available. Install RSAT and retry."
    exit 1
}

# ---------------------------------------------------------------------------
# [1/5] Discover all domains in the forest
# ---------------------------------------------------------------------------
Write-Host "[1/5] Discovering forest domains..." -ForegroundColor Yellow

try {
    $Forest  = Get-ADForest -Identity $ForestRootDomain
    $Domains = @($Forest.RootDomain) + @($Forest.Domains | Where-Object { $_ -ne $Forest.RootDomain })
    Write-Host "      Found $($Domains.Count) domain(s):" -ForegroundColor Green
    $Domains | ForEach-Object { Write-Host "        - $_" }
} catch {
    Write-Error "Failed to enumerate forest: $_"
    exit 1
}

# ---------------------------------------------------------------------------
# [2/5] Collect account data from all domains
# ---------------------------------------------------------------------------
Write-Host ""
Write-Host "[2/5] Auditing accounts across all domains..." -ForegroundColor Yellow

$AccountResults = New-Object System.Collections.Generic.List[PSCustomObject]

foreach ($Domain in $Domains) {
    Write-Host "  -> $Domain" -NoNewline

    try {
        $DC = (Get-ADDomainController -DomainName $Domain -Discover -Service PrimaryDC).HostName[0]

        # -- User accounts --------------------------------------------------
        $Users = Get-ADUser -Filter * -Server $DC -Properties `
            msDS-SupportedEncryptionTypes, `
            ServicePrincipalNames, `
            PasswordLastSet, `
            LastLogonDate, `
            Enabled, `
            Description, `
            DistinguishedName, `
            WhenCreated, `
            adminCount `
            -ErrorAction SilentlyContinue

        foreach ($User in $Users) {
            # FIX: Safely cast msDS-SupportedEncryptionTypes - attribute may be $null
            $rawEnc  = $User.'msDS-SupportedEncryptionTypes'
            $encMask = if ($null -ne $rawEnc) { [int]$rawEnc } else { 0 }

            $rc4     = Test-RC4Enabled -Mask $encMask
            $aesOnly = Test-AES256Only -Mask $encMask

            $spnList = $User.ServicePrincipalNames
            $hasSPN  = ($null -ne $spnList) -and ($spnList.Count -gt 0)
            $spnStr  = if ($hasSPN) { $spnList -join ";" } else { "" }

            # FIX: Safely handle $null adminCount under StrictMode
            $adminCnt = if ($null -ne $User.adminCount) { [int]$User.adminCount } else { 0 }

            $riskLevel = if (-not $rc4) {
                "Low"
            } elseif ($hasSPN) {
                "Critical"
            } elseif ($adminCnt -gt 0) {
                "High"
            } else {
                "Medium"
            }

            $AccountResults.Add([PSCustomObject]@{
                RecordType          = "Account"
                Domain              = $Domain
                SamAccountName      = $User.SamAccountName
                DisplayName         = $User.Name
                ObjectType          = if ($hasSPN) { "Service Account (User)" } else { "User" }
                EncryptionTypeMask  = $encMask
                EncryptionTypes     = Get-EncryptionTypes -Mask $encMask
                RC4Enabled          = $rc4
                AES256Only          = $aesOnly
                Enabled             = $User.Enabled
                PasswordLastSet     = $User.PasswordLastSet
                LastLogonDate       = $User.LastLogonDate
                AdminCount          = $adminCnt
                SPNs                = $spnStr
                HasSPN              = $hasSPN
                DistinguishedName   = $User.DistinguishedName
                WhenCreated         = $User.WhenCreated
                Description         = $User.Description
                RiskLevel           = $riskLevel
                AuditTimestamp      = (Get-Date -Format "yyyy-MM-dd HH:mm:ss")
            })
        }

        # -- Computer accounts ----------------------------------------------
        $Computers = Get-ADComputer -Filter * -Server $DC -Properties `
            msDS-SupportedEncryptionTypes, `
            ServicePrincipalNames, `
            LastLogonDate, `
            Enabled, `
            OperatingSystem, `
            DistinguishedName, `
            WhenCreated `
            -ErrorAction SilentlyContinue

        foreach ($Comp in $Computers) {
            $rawEnc  = $Comp.'msDS-SupportedEncryptionTypes'
            $encMask = if ($null -ne $rawEnc) { [int]$rawEnc } else { 0 }

            $rc4     = Test-RC4Enabled -Mask $encMask
            $aesOnly = Test-AES256Only -Mask $encMask

            $AccountResults.Add([PSCustomObject]@{
                RecordType          = "Account"
                Domain              = $Domain
                SamAccountName      = $Comp.SamAccountName
                DisplayName         = $Comp.Name
                ObjectType          = "Computer"
                EncryptionTypeMask  = $encMask
                EncryptionTypes     = Get-EncryptionTypes -Mask $encMask
                RC4Enabled          = $rc4
                AES256Only          = $aesOnly
                Enabled             = $Comp.Enabled
                PasswordLastSet     = ""
                LastLogonDate       = $Comp.LastLogonDate
                AdminCount          = 0
                SPNs                = ($Comp.ServicePrincipalNames -join ";")
                HasSPN              = ($Comp.ServicePrincipalNames.Count -gt 0)
                DistinguishedName   = $Comp.DistinguishedName
                WhenCreated         = $Comp.WhenCreated
                Description         = $Comp.OperatingSystem
                RiskLevel           = if (-not $rc4) { "Low" } else { "Medium" }
                AuditTimestamp      = (Get-Date -Format "yyyy-MM-dd HH:mm:ss")
            })
        }

        # -- gMSA accounts --------------------------------------------------
        try {
            $gMSAs = Get-ADServiceAccount -Filter * -Server $DC -Properties `
                msDS-SupportedEncryptionTypes, `
                ServicePrincipalNames, `
                Enabled, `
                DistinguishedName, `
                WhenCreated `
                -ErrorAction SilentlyContinue

            foreach ($gMSA in $gMSAs) {
                $rawEnc  = $gMSA.'msDS-SupportedEncryptionTypes'
                $encMask = if ($null -ne $rawEnc) { [int]$rawEnc } else { 0 }

                $rc4     = Test-RC4Enabled -Mask $encMask
                $aesOnly = Test-AES256Only -Mask $encMask

                $gHasSPN = ($gMSA.ServicePrincipalNames.Count -gt 0)

                $AccountResults.Add([PSCustomObject]@{
                    RecordType          = "Account"
                    Domain              = $Domain
                    SamAccountName      = $gMSA.SamAccountName
                    DisplayName         = $gMSA.Name
                    ObjectType          = "gMSA"
                    EncryptionTypeMask  = $encMask
                    EncryptionTypes     = Get-EncryptionTypes -Mask $encMask
                    RC4Enabled          = $rc4
                    AES256Only          = $aesOnly
                    Enabled             = $gMSA.Enabled
                    PasswordLastSet     = ""
                    LastLogonDate       = ""
                    AdminCount          = 0
                    SPNs                = ($gMSA.ServicePrincipalNames -join ";")
                    HasSPN              = $gHasSPN
                    DistinguishedName   = $gMSA.DistinguishedName
                    WhenCreated         = $gMSA.WhenCreated
                    Description         = "gMSA"
                    RiskLevel           = if (-not $rc4) { "Low" } elseif ($gHasSPN) { "High" } else { "Medium" }
                    AuditTimestamp      = (Get-Date -Format "yyyy-MM-dd HH:mm:ss")
                })
            }
        } catch {
            Write-Host " [gMSA query failed - skipping]" -NoNewline -ForegroundColor DarkYellow
        }

        $DomainCount = ($AccountResults | Where-Object { $_.Domain -eq $Domain }).Count
        Write-Host " OK ($DomainCount objects)" -ForegroundColor Green

    } catch {
        Write-Host " ERROR: $_" -ForegroundColor Red
    }
}

$AccountResults | Export-Csv -Path $AccountsCSV -NoTypeInformation -Encoding UTF8
Write-Host "  Accounts CSV : $AccountsCSV" -ForegroundColor DarkGray

# ---------------------------------------------------------------------------
# [3/5] KDC Event Log - Event 4769 RC4 ticket requests
# ---------------------------------------------------------------------------
$EventLogResults = New-Object System.Collections.Generic.List[PSCustomObject]

if (-not $SkipEventLog) {
    Write-Host ""
    Write-Host "[3/5] Collecting KDC Event Log (Event 4769) from PDC Emulators..." -ForegroundColor Yellow
    Write-Host "      Looking back $EventLogHours hours"

    $StartTime = (Get-Date).AddHours(-$EventLogHours)

    # Build ISO8601 timestamp for the XPath filter - must be done outside the here-string
    # to avoid complex expression parsing issues in PS5
    $StartTimeISO = $StartTime.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffZ")

    foreach ($Domain in $Domains) {
        Write-Host "  -> $Domain" -NoNewline
        try {
            $PDC = (Get-ADDomainController -DomainName $Domain -Discover -Service PrimaryDC).HostName[0]

            # FIX: Build FilterXML with pre-computed timestamp variable (no method calls inside here-string)
            $FilterXML = @"
<QueryList>
  <Query Id="0" Path="Security">
    <Select Path="Security">
      *[System[(EventID=4769) and TimeCreated[@SystemTime&gt;='$StartTimeISO']]]
      and
      *[EventData[Data[@Name='TicketEncryptionType'] and (Data='0x17' or Data='0x3')]]
    </Select>
  </Query>
</QueryList>
"@
            $Events = Get-WinEvent -ComputerName $PDC -FilterXml $FilterXML -ErrorAction SilentlyContinue |
                      Select-Object -First 5000

            $Events | ForEach-Object {
                $xml = [xml]$_.ToXml()
                $ed  = $xml.Event.EventData.Data
                $EventLogResults.Add([PSCustomObject]@{
                    RecordType    = "EventLog"
                    Domain        = $Domain
                    PDCEmulator   = $PDC
                    TimeCreated   = $_.TimeCreated
                    ServiceName   = ($ed | Where-Object { $_.Name -eq "ServiceName"           }).'#text'
                    ClientAddress = ($ed | Where-Object { $_.Name -eq "IpAddress"             }).'#text'
                    AccountName   = ($ed | Where-Object { $_.Name -eq "TargetUserName"        }).'#text'
                    TicketEncType = ($ed | Where-Object { $_.Name -eq "TicketEncryptionType"  }).'#text'
                    FailureCode   = ($ed | Where-Object { $_.Name -eq "Status"                }).'#text'
                    AuditTimestamp = (Get-Date -Format "yyyy-MM-dd HH:mm:ss")
                })
            }

            Write-Host " OK ($($Events.Count) RC4 ticket events)" -ForegroundColor Green

        } catch {
            # FIX: Avoid .Split() on potentially null exception message
            $errMsg = if ($_.Exception.Message) { $_.Exception.Message.Split('.')[0] } else { "Unknown error" }
            Write-Host " SKIPPED - $errMsg" -ForegroundColor DarkYellow
        }
    }

    if ($EventLogResults.Count -gt 0) {
        $EventLogResults | Export-Csv -Path $EventLogCSV -NoTypeInformation -Encoding UTF8
        Write-Host "  EventLog CSV : $EventLogCSV" -ForegroundColor DarkGray
    } else {
        Write-Host "  No RC4 ticket events found in the $EventLogHours hour window." -ForegroundColor DarkGray
    }

} else {
    Write-Host ""
    Write-Host "[3/5] KDC Event Log collection SKIPPED (-SkipEventLog specified)" -ForegroundColor DarkYellow
}

# ---------------------------------------------------------------------------
# [4/5] GPO audit - Kerberos settings
# ---------------------------------------------------------------------------
Write-Host ""
Write-Host "[4/5] Auditing Group Policy Kerberos settings..." -ForegroundColor Yellow

$GPOResults = New-Object System.Collections.Generic.List[PSCustomObject]

try {
    Import-Module GroupPolicy -ErrorAction Stop

    foreach ($Domain in $Domains) {
        Write-Host "  -> $Domain" -NoNewline
        try {
            $GPOs = Get-GPO -All -Domain $Domain -ErrorAction SilentlyContinue

            foreach ($GPO in $GPOs) {
                try {
                    $Report = Get-GPOReport -Guid $GPO.Id -ReportType Xml -Domain $Domain -ErrorAction SilentlyContinue
                    if ($null -eq $Report) { continue }

                    $reportText       = $Report
                    $hasRC4Setting    = $reportText -match "RC4|SupportedEncryptionTypes"
                    $hasAES256Setting = $reportText -match "AES256|0x18"
                    $hasKerb          = $reportText -match "Kerberos|kerberos"

                    if ($hasRC4Setting -or $hasAES256Setting -or $hasKerb) {
                        # FIX: Safely handle $null WmiFilter
                        $wmiName = if ($null -ne $GPO.WmiFilter) { $GPO.WmiFilter.Name } else { "" }

                        $GPOResults.Add([PSCustomObject]@{
                            RecordType          = "GPO"
                            Domain              = $Domain
                            GPOName             = $GPO.DisplayName
                            GPOId               = $GPO.Id.ToString()
                            GPOStatus           = $GPO.GpoStatus.ToString()
                            LinkedTo            = "See GPMC for links"
                            HasKerberosSettings = $hasKerb
                            ReferencesRC4       = $hasRC4Setting
                            ReferencesAES256    = $hasAES256Setting
                            WMIFilter           = $wmiName
                            ModificationTime    = $GPO.ModificationTime
                            AuditTimestamp      = (Get-Date -Format "yyyy-MM-dd HH:mm:ss")
                            Notes               = "Review manually in GPMC for exact SupportedEncryptionTypes value"
                        })
                    }
                } catch {
                    # Skip individual GPO report failures silently
                }
            }

            $DomainGPOs = ($GPOResults | Where-Object { $_.Domain -eq $Domain }).Count
            Write-Host " OK ($DomainGPOs relevant GPOs)" -ForegroundColor Green

        } catch {
            Write-Host " ERROR: $_" -ForegroundColor Red
        }
    }

    if ($GPOResults.Count -gt 0) {
        $GPOResults | Export-Csv -Path $GPOSettingsCSV -NoTypeInformation -Encoding UTF8
        Write-Host "  GPO CSV : $GPOSettingsCSV" -ForegroundColor DarkGray
    }

} catch {
    Write-Host "  GroupPolicy module not available - skipping GPO audit" -ForegroundColor DarkYellow
}

# ---------------------------------------------------------------------------
# [5/5] Build summary and master CSV
# ---------------------------------------------------------------------------
Write-Host ""
Write-Host "[5/5] Building summary and master CSV..." -ForegroundColor Yellow

$SummaryRows = New-Object System.Collections.Generic.List[PSCustomObject]

foreach ($Domain in $Domains) {
    $DomainAccounts = @($AccountResults | Where-Object { $_.Domain -eq $Domain })
    $TotalObjects   = $DomainAccounts.Count
    $RC4Objects     = @($DomainAccounts | Where-Object { $_.RC4Enabled -eq $true }).Count
    $AES256Only     = @($DomainAccounts | Where-Object { $_.AES256Only -eq $true }).Count
    $CriticalRisk   = @($DomainAccounts | Where-Object { $_.RiskLevel -eq "Critical" }).Count
    $HighRisk       = @($DomainAccounts | Where-Object { $_.RiskLevel -eq "High" }).Count
    $UserRC4        = @($DomainAccounts | Where-Object { $_.RC4Enabled -eq $true -and $_.ObjectType -match "User" }).Count
    $ComputerRC4    = @($DomainAccounts | Where-Object { $_.RC4Enabled -eq $true -and $_.ObjectType -eq "Computer" }).Count
    $SvcAccRC4      = @($DomainAccounts | Where-Object { $_.RC4Enabled -eq $true -and $_.ObjectType -match "Service|gMSA" }).Count
    $SPNRC4         = @($DomainAccounts | Where-Object { $_.RC4Enabled -eq $true -and $_.HasSPN -eq $true }).Count
    $RC4Pct         = if ($TotalObjects -gt 0) { [math]::Round(($RC4Objects / $TotalObjects) * 100, 1) } else { 0 }
    $EventCount     = @($EventLogResults | Where-Object { $_.Domain -eq $Domain }).Count
    $GPOCount       = @($GPOResults      | Where-Object { $_.Domain -eq $Domain }).Count

    $SummaryRows.Add([PSCustomObject]@{
        RecordType           = "Summary"
        Domain               = $Domain
        TotalObjects         = $TotalObjects
        RC4ExposedObjects    = $RC4Objects
        AES256OnlyObjects    = $AES256Only
        RC4Percent           = $RC4Pct
        CriticalRiskCount    = $CriticalRisk
        HighRiskCount        = $HighRisk
        UsersWithRC4         = $UserRC4
        ComputersWithRC4     = $ComputerRC4
        ServiceAccountsRC4   = $SvcAccRC4
        SPNsWithRC4          = $SPNRC4
        KDCEventCount        = $EventCount
        GPOsWithKerbSettings = $GPOCount
        AuditTimestamp       = (Get-Date -Format "yyyy-MM-dd HH:mm:ss")
    })
}

$SummaryRows | Export-Csv -Path $SummaryCSV -NoTypeInformation -Encoding UTF8

# ---------------------------------------------------------------------------
# Build master CSV
# FIX: Each record type has different columns. Export-Csv in PS5 uses the
# first object's properties as the header, silently dropping columns from
# subsequent objects with different schemas.
# Solution: explicitly select a unified superset of columns for all rows,
# padding missing fields with empty strings so all rows share one schema.
# ---------------------------------------------------------------------------

$MasterColumns = @(
    "RecordType","Domain","SamAccountName","DisplayName","ObjectType",
    "EncryptionTypeMask","EncryptionTypes","RC4Enabled","AES256Only",
    "Enabled","PasswordLastSet","LastLogonDate","AdminCount","SPNs","HasSPN",
    "DistinguishedName","WhenCreated","Description","RiskLevel",
    # EventLog columns
    "PDCEmulator","TimeCreated","ServiceName","ClientAddress","AccountName",
    "TicketEncType","FailureCode",
    # GPO columns
    "GPOName","GPOId","GPOStatus","LinkedTo","HasKerberosSettings",
    "ReferencesRC4","ReferencesAES256","WMIFilter","ModificationTime","Notes",
    # Summary columns
    "TotalObjects","RC4ExposedObjects","AES256OnlyObjects","RC4Percent",
    "CriticalRiskCount","HighRiskCount","UsersWithRC4","ComputersWithRC4",
    "ServiceAccountsRC4","SPNsWithRC4","KDCEventCount","GPOsWithKerbSettings",
    # Common
    "AuditTimestamp"
)

$AllRows = New-Object System.Collections.Generic.List[PSCustomObject]

$AllSources = @(
    [PSCustomObject]@{ Data = $AccountResults;  Type = "Account"  }
    [PSCustomObject]@{ Data = $EventLogResults; Type = "EventLog" }
    [PSCustomObject]@{ Data = $GPOResults;      Type = "GPO"      }
    [PSCustomObject]@{ Data = $SummaryRows;     Type = "Summary"  }
)

foreach ($Source in $AllSources) {
    foreach ($Row in $Source.Data) {
        # Build a new object with ALL master columns, defaulting missing ones to ""
        $newRow = [ordered]@{}
        foreach ($Col in $MasterColumns) {
            $val = $Row.PSObject.Properties[$Col]
            $newRow[$Col] = if ($null -ne $val) { $val.Value } else { "" }
        }
        $AllRows.Add([PSCustomObject]$newRow)
    }
}

$AllRows | Export-Csv -Path $MasterCSV -NoTypeInformation -Encoding UTF8

# ---------------------------------------------------------------------------
# Final summary to console
# ---------------------------------------------------------------------------
$TotalRC4 = ($AccountResults | Where-Object { $_.RC4Enabled -eq $true }).Count
$TotalAll = $AccountResults.Count

Write-Host ""
Write-Host "=================================================" -ForegroundColor Green
Write-Host "   AUDIT COMPLETE - SUMMARY" -ForegroundColor Green
Write-Host "=================================================" -ForegroundColor Green
Write-Host ""
Write-Host "  Total objects audited  : $TotalAll"

$rc4Color = if ($TotalRC4 -gt 0) { "Red" } else { "Green" }
Write-Host "  RC4-exposed objects    : $TotalRC4" -ForegroundColor $rc4Color

$evtColor = if ($EventLogResults.Count -gt 0) { "Yellow" } else { "Green" }
Write-Host "  KDC RC4 ticket events  : $($EventLogResults.Count)" -ForegroundColor $evtColor

Write-Host "  GPOs with Kerb config  : $($GPOResults.Count)"
Write-Host ""
Write-Host "  Output files:"
Write-Host "    Accounts   : $AccountsCSV"
if (-not $SkipEventLog -and $EventLogResults.Count -gt 0) {
    Write-Host "    Event Log  : $EventLogCSV"
}
if ($GPOResults.Count -gt 0) {
    Write-Host "    GPO        : $GPOSettingsCSV"
}
Write-Host "    Summary    : $SummaryCSV"
Write-Host "    MASTER     : $MasterCSV" -ForegroundColor Cyan
Write-Host ""
Write-Host "  Load $MasterCSV into the RC4 Dashboard HTML file" -ForegroundColor Yellow
Write-Host "  Completed : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
Write-Host ""
