# Microsoft Graph Sign-in Audit & AbuseIPDB Threat Intel (`graph_signins_abuseip.py`)

A security-focused investigation tool designed for SOC analysts, incident responders, and Entra ID administrators. It queries authentication logs from the **Microsoft Graph API (`/auditLogs/signIns`)** using interactive PKCE authentication and enriches each unique source IP with real-time threat intelligence from the **AbuseIPDB API v2**. It exports structured CSV reports and generates an interactive, client-side HTML dashboard.

---

## Table of Contents

1. [Features](#1-features)
2. [How It Works](#2-how-it-works)
3. [Prerequisites & Dependencies](#3-prerequisites--dependencies)
4. [Installation & Configuration](#4-installation--configuration)
   - [Step 1: Install Dependencies](#step-1-install-dependencies)
   - [Step 2: Configure AbuseIPDB API Keys](#step-2-configure-abuseipdb-api-keys)
5. [Usage & Execution](#5-usage--execution)
   - [1. Default Execution (Last 15 Days, Quiet Progress Mode)](#1-default-execution-last-15-days-quiet-progress-mode)
   - [2. Custom Time Window (-d)](#2-custom-time-window--d)
   - [3. Verbose Mode (-v)](#3-verbose-mode--v)
   - [Command-Line Arguments Reference](#command-line-arguments-reference)
6. [Generated Outputs](#6-generated-outputs)
7. [Corporate Proxy & SSL Troubleshooting](#7-corporate-proxy--ssl-troubleshooting)

---

## 1. Features

- **No Custom Azure App Registration Needed**: Uses the official Microsoft Azure CLI public Client ID (`04b07795-8ddb-461a-bbee-02f9e1bf7b46`) with browser-based interactive PKCE login.
- **Account Selection Prompt**: Forces the Microsoft account picker (`prompt="select_account"`) to easily select or switch administrative/analyst identities.
- **Automatic Email Normalization**: Trims whitespace and enforces lowercase conversion on target user inputs to ensure accurate OData querying.
- **Customizable Time Range (`-d` / `--days`)**: Queries sign-in events within a dynamic timeframe (defaults to the past 15 days).
- **AbuseIPDB Threat Intelligence**: Automatically evaluates every login IP against AbuseIPDB to retrieve Abuse Confidence Score, total reports, ISP, and attack categories (e.g., Brute-Force, SSH, Web App Attack).
- **In-Memory IP Caching & Private IP Filter**: Evaluates duplicate IPs only once per run to preserve API quota, and skips non-routable private IP addresses (RFC 1918 / Loopback) automatically.
- **API Key Rotation Pool**: Cycles sequentially through multiple AbuseIPDB API keys whenever an HTTP 429 rate limit is reached.
- **Error Code Translation**: Maps common Microsoft Entra ID authentication error codes (e.g., `50126`, `50053`, `53003`) into clear, human-readable explanations.
- **Dual Console Modes**:
  - **Quiet Mode (Default)**: Inline percentage progress bars for each stage and a clean summary box at the end.
  - **Verbose Mode (`-v`)**: Real-time event-by-event output with terminal colors and full metadata.
- **Automated CSV Export**: Produces a timestamped, UTF-8-BOM encoded `.csv` file containing full event metadata and threat intelligence ratings.
- **Interactive HTML Dashboard**: Builds a self-contained report featuring real-time client-side search, summary metric cards, quick filters (*All / Success / Failure / Malicious / Suspicious / Clean*), sticky headers, and sub-text error descriptions.
- **Corporate Proxy & SSL Ready**: Preconfigured with `verify=False` and suppressed `urllib3` warnings to operate cleanly within corporate networks undergoing SSL/TLS inspection.

---

## 2. How It Works

1. **Interactive Authentication**: MSAL initializes a `PublicClientApplication` and requests the delegated scope `https://graph.microsoft.com/AuditLog.Read.All`. The local system launches the default web browser, allowing the analyst to authenticate and complete MFA.
2. **OData Query Construction**: A UTC-based cutoff timestamp is calculated using the configured day offset. An OData filter string is formed:
   ```text
   userPrincipalName eq '<user>' and createdDateTime ge <UTC_DATE>
   ```
3. **Log Retrieval & Pagination**: Performs HTTP GET requests to `https://graph.microsoft.com/v1.0/auditLogs/signIns`. If `@odata.nextLink` is present, it paginates until all records are retrieved.
4. **Threat Intelligence Enrichment**:
   - Inspects the source IP address of each record.
   - If private, tags it as internal without spending external API queries.
   - If public and not previously seen in memory, queries the AbuseIPDB `/check` endpoint and caches the score and metadata.
   - Rotates to the next available API key if rate limits occur.
5. **Output & Report Generation**:
   - Outputs the final summary to the console.
   - Exports all raw and enriched data to `signins_intel_<user>_<days>d_<timestamp>.csv`.
   - Generates the standalone `signins_intel_<user>_<days>d_<timestamp>.html` dashboard.

---

## 3. Prerequisites & Dependencies

### Python Environment
- Python 3.8+ (Standard Python or Anaconda/Miniconda)
- Required Python libraries:
  - `msal`
  - `requests`
  - `urllib3`

### Azure / Microsoft Entra ID Requirements
- **Tenant License**: Microsoft Entra ID P1 or P2 (or licensing bundles such as Microsoft 365 E3/E5).
- **Delegated Permission**: `AuditLog.Read.All`.
- **Directory Roles (User Level)**: The analyst account performing the browser login must possess at least one of the following roles:
  - *Security Reader* (Recommended for SOC analysts)
  - *Reports Reader*
  - *Global Reader*
  - *Security Administrator*
  - *Global Administrator*

### AbuseIPDB Requirements
- One or more free or paid API keys from [AbuseIPDB](https://www.abuseipdb.com/).

---

## 4. Installation & Configuration

### Step 1: Install Dependencies

#### Option 1: Using Anaconda (Recommended)
1. Open **Anaconda Prompt**.
2. Run:
   ```bash
   conda install requests
   pip install msal urllib3
   ```
   *(Confirm with `y` if prompted)*.

#### Option 2: Using Standard Python (CMD / PowerShell / macOS / Linux)
1. Open your terminal.
2. Run:
   ```bash
   pip install msal requests urllib3
   ```

### Step 2: Configure AbuseIPDB API Keys

1. Open `graph_signins_abuseip.py` in an editor (VS Code, Notepad, Vim).
2. Locate the `ABUSEIPDB_API_KEYS` list near the top of the file and paste your API key(s):
   ```python
   # =========================================================================
   # CONFIGURATION
   # =========================================================================
   ABUSEIPDB_API_KEYS = [
       "YOUR_ABUSEIPDB_KEY_1",
       "YOUR_ABUSEIPDB_KEY_2"
   ]
   # =========================================================================
   ```
3. Save the file.

---

## 5. Usage & Execution

Navigate to the directory containing the script:
```bash
cd "C:\Path\To\Script"
```

### 1. Default Execution (Last 15 Days, Quiet Progress Mode)
```bash
python graph_signins_abuseip.py -u user@company.com
```
*Displays progress percentages for each step and prints the statistical summary at the end without cluttering the terminal.*

### 2. Custom Time Window (-d)
Specify the number of past days to query (e.g., last 7 days or 30 days):
```bash
python graph_signins_abuseip.py -u user@company.com -d 7
python graph_signins_abuseip.py -u user@company.com -d 30
```

### 3. Verbose Mode (-v)
Outputs full metadata for every single sign-in event directly to the console:
```bash
python graph_signins_abuseip.py -u user@company.com -v
python graph_signins_abuseip.py -u user@company.com -d 30 -v
```

### Command-Line Arguments Reference

| Argument | Type | Default | Required | Description |
| :--- | :--- | :--- | :--- | :--- |
| `-u`, `--user` | String | *None* | **Yes** | Target UserPrincipalName or corporate email address. |
| `-d`, `--days` | Integer | `15` | No | Number of past days to query from current UTC time. |
| `-v`, `--verbose` | Flag | `False` | No | Enables detailed event-by-event terminal output. |

---

## 6. Generated Outputs

### 1. Terminal Summary Box
```text
=====================================================================================
 SIGN-IN EVENTS SUMMARY (15 DAYS) | UNIQUE IPs CHECKED: 4
=====================================================================================
 Total Logins   : 28
 Successful     : 25
 Failed         : 3
 Unique IPs     : 4
=====================================================================================
```


### 2. CSV Report (`signins_intel_<user>_<days>d_<timestamp>.csv`)
Full tabular event export suitable for Excel or SIEM ingestion, including timestamps, user, application, status, error code, failure description, IP, location, OS, browser, Conditional Access policies, Abuse Score, Abuse Reports count, and attack categories.

### 3. Interactive HTML Dashboard (`signins_intel_<user>_<days>d_<timestamp>.html`)
Standalone report viewable in any browser featuring:
- Summary metric cards (*Total Logs, Success, Failures, Malicious IPs, Suspicious IPs*).
- Instant live search by IP, app, browser, date, error reason, or attack type.
- One-click filters (*All / Success / Failure / Malicious / Suspicious / Clean*).
- Abuse confidence progress bars and threat category badges.
- Error explanations rendered under failed login codes.

---

## 7. Corporate Proxy & SSL Troubleshooting

When executing inside corporate networks with SSL/TLS inspection, certificate verification errors may occur. The script natively handles this behavior by:
1. Disabling insecure request warnings:
   ```python
   import urllib3
   urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
   ```
2. Setting `verify=False` within all Graph API and AbuseIPDB requests:
   ```python
   requests.get(url, headers=headers, verify=False)
   ```