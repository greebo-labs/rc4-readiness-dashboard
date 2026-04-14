# RC4 Deprecation Readiness Audit

PowerShell audit tooling and a browser-based dashboard for assessing Active Directory RC4 exposure ahead of Kerberos RC4 deprecation.

This repository packages two companion files:

- `Invoke-RC4Audit.ps1` — a read-only forest-wide audit script for collecting RC4 exposure, KDC event log activity, and Kerberos-related GPO findings.
- `RC4_Dashboard.html` — a standalone HTML dashboard that loads the unified master CSV from the audit script and presents executive, operational, and remediation views.

## What this does

The script audits:

- User accounts
- Service accounts
- Computer accounts
- gMSAs
- KDC Security log activity (Event ID 4769 for RC4/DES ticket activity)
- GPOs that reference Kerberos / encryption settings

It then writes a set of CSV outputs, including a master CSV that can be opened in the dashboard.

## Repository layout

```text
.
├── Invoke-RC4Audit.ps1
├── RC4_Dashboard.html
├── README.md
├── .gitignore
└── docs
    ├── README.md
    ├── PUBLISH-TO-GITHUB.md
    └── TROUBLESHOOTING.md
```

## Requirements

### PowerShell / AD audit

- Windows PowerShell 5.1+
- RSAT Active Directory module
- RSAT Group Policy module for GPO inspection
- Domain Admin or delegated read rights across the forest
- Remote access to each domain's PDC emulator if event log collection is enabled

### Dashboard

- Modern browser such as Microsoft Edge or Google Chrome
- Internet access to fetch the CDN-hosted JavaScript/CSS dependencies used by the dashboard

## Quick start

### 1) Run the audit

```powershell
.\Invoke-RC4Audit.ps1 -ForestRootDomain "corp.internal" -OutputPath "C:\RC4_Audit"
```

Optional examples:

```powershell
.\Invoke-RC4Audit.ps1 -ForestRootDomain "corp.internal" -SkipEventLog
.\Invoke-RC4Audit.ps1 -ForestRootDomain "corp.internal" -EventLogHours 168
```

### 2) Open the dashboard

Open `RC4_Dashboard.html` in a browser and load:

```text
RC4_Master_YYYYMMDD_HHMMSS.csv
```

## Output files

The script writes these CSV files to the chosen output folder:

- `RC4_Accounts_*.csv`
- `RC4_EventLog_*.csv` (when event log collection is enabled and data is found)
- `RC4_GPO_*.csv` (when the GroupPolicy module is available and relevant GPOs are found)
- `RC4_Summary_*.csv`
- `RC4_Master_*.csv`

## Dashboard views

The HTML dashboard includes:

- Executive Summary
- RC4 Exposure
- Domain Breakdown
- Object Detail
- KDC Event Log
- GPO Settings
- Remediation Plan

## Operational notes

- The PowerShell audit is read-only. It does not modify AD.
- The dashboard processes data in the browser.
- The dashboard includes organization-specific author/footer text and an internal-use disclaimer. Review and edit that wording before any external sharing.
- The dashboard uses CDN-hosted dependencies (`PapaParse`, `Chart.js`, and Google Fonts). If you need a fully offline version, those libraries should be vendored locally and the HTML references updated.

## Recommended repository visibility

Because the dashboard footer and source comments label the solution as internal-use and the files can expose AD naming conventions, **private repository visibility is recommended**.

## Included documentation

See `docs/` for setup guidance, publishing notes, and troubleshooting.
