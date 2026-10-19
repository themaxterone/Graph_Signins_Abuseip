# Microsoft Graph Sign-in Audit & AbuseIPDB Threat Intel (`graph_signins_abuseip.py`)

A security investigation tool designed for SOC analysts and incident responders that retrieves user authentication events from **Microsoft Graph API (`/auditLogs/signIns`)** and automatically enriches each unique source IP address with real-time threat intelligence from the **AbuseIPDB API v2**.

---

## 1. Features

- **No Custom Azure App Registration Needed**: Uses the official Microsoft Azure CLI public Client ID (`04b07795-8ddb-461a-bbee-02f9e1bf7b46`) with browser-based interactive PKCE authentication.
- **Account Selection Prompt**: Forces the Microsoft account picker (`prompt="select_account"`) to easily select or switch administrative/analyst credentials.
- **Email Normalization**: Strips spaces and enforces lowercase conversion on target user inputs to avoid OData query mismatches.
- **Dynamic Time Range (`-d` / `--days`)**: Queries sign-in events within a custom timeframe (defaults to the past 15 days).
- **AbuseIPDB Threat Intelligence**: Enriches sign-in events with the Abuse Confidence Score, total report count, ISP, and attack categories (e.g., Brute-Force, SSH, Web App Attack).
- **API Key Rotation & Multi-Key Support**: Cycles through a pool of AbuseIPDB API keys automatically whenever a rate limit (HTTP 429) is reached.
- **In-Memory IP Caching & Private IP Filter**: Caches queried IPs so duplicate IP addresses are inspected only once, saving quota and skipping non-routable private IP addresses.
- **Dual Console Modes (`-v` / `--verbose`)**:
  - **Quiet Mode (Default)**: Displays single-line percentage progress bars for each phase and finishes with a summary metrics box.
  - **Verbose Mode (`-v`)**: Prints real-time event-by-event breakdowns with color-coded authentication status and IP threat details.
- **Automated Reporting**:
  - **CSV File**: Formatted UTF-8-BOM spreadsheet containing all sign-in parameters and threat intel values.
  - **Interactive HTML Dashboard**: Self-contained web report with live keyword search, status filters (*All / Success / Failure*), risk filters (*Malicious / Suspicious / Clean*), progress bars, and error code explanations.
- **Corporate Proxy & SSL Ready**: Configured with `verify=False` and suppressed `urllib3` warnings to operate cleanly within enterprise networks undergoing SSL/TLS inspection[cite: 1, 2].

---

## 2. How It Works

1. **Authentication**: The script initializes MSAL with public delegated permissions (`https://graph.microsoft.com/AuditLog.Read.All`) and launches your default browser to complete authentication and MFA.
2. **Querying Sign-in Logs**: Calculates the cutoff date (UTC) based on the specified timeframe and queries `https://graph.microsoft.com/v1.0/auditLogs/signIns`, traversing `@odata.nextLink` to collect all paginated events.
3. **Threat Intel Enrichment**:
   - Evaluates each source IP address. If it is a private IP, it marks it as *Internal*.
   - If public, checks the local in-memory cache. If unseen, queries the AbuseIPDB API (`/api/v2/check`).
   - If an AbuseIPDB key hits an HTTP 429 rate limit, it automatically rotates to the next key in the configured list.
4. **Summary & Export**:
   - Generates an analytical summary in the terminal (total logins, successes, failures, unique IPs checked).
   - Generates a timestamped `.csv` file.
   - Builds a responsive, standalone `.html` dashboard viewable in any modern web browser.

---

## 3. Prerequisites & Dependencies

### Python Environment
- Python 3.8+ (Standard Python or Anaconda/Miniconda)
- Required libraries:
  - `msal`
  - `requests`
  - `urllib3`

### Azure / Microsoft Entra ID Requirements
- **Tenant License**: Microsoft Entra ID P1 or P2 (or licensing bundles like Microsoft 365 E3/E5).
- **Directory Roles (User Level)**: The analyst account performing the browser login must possess at least one of the following roles:
  - *Security Reader* (Recommended for SOC analysts)
  - *Reports Reader*
  - *Global Reader*
  - *Security Administrator*
  - *Global Administrator*

### AbuseIPDB Requirements
- One or more free/paid API keys from [AbuseIPDB](https://www.abuseipdb.com/).

---

## 4. Installation & Configuration

### Step 1: Install Dependencies

#### Using Anaconda (Recommended)
```bash
pip install msal requests urllib3 
```

#### Using Standard Python (CMD / PowerShell / Bash)
```
pip install msal requests urllib3
```

### Step 2: Configure AbuseIPDB API Keys

- Open graph_signins_abuseip.py in a text editor and paste your API key(s) into the ABUSEIPDB_API_KEYS list:

```
# =========================================================================
# CONFIGURATION
# =========================================================================
ABUSEIPDB_API_KEYS = [
    "YOUR_ABUSEIPDB_KEY_1",
    "YOUR_ABUSEIPDB_KEY_2"
]
# =========================================================================
```
---
## 5. Usage & Execution

### 1. Default Execution (Last 15 Days, Quiet Progress Mode)

```
python graph_signins_abuseip.py -u user@company.com
```

### 2. Custom Time Window (-d)

- Specify the number of past days to query (e.g., last 7 days or 30 days):

```
python graph_signins_abuseip.py -u user@company.com -d 7
python graph_signins_abuseip.py -u user@company.com -d 30
```

### 3. Verbose Mode (-v)

- Outputs detailed metadata for every single sign-in event directly to the console:

```
python graph_signins_abuseip.py -u user@company.com -v
python graph_signins_abuseip.py -u user@company.com -d 30 -v
```
---
## 6. Generated Outputs

- Terminal Summary:

```
=====================================================================================
 SIGN-IN EVENTS SUMMARY (15 DAYS) | UNIQUE IPs CHECKED: 4
=====================================================================================
 Total Logins   : 28
 Successful     : 25
 Failed         : 3
 Unique IPs     : 4
=====================================================================================
```

- **CSV Report** (signins_intel_<user>_<days>d_<timestamp>.csv): Full tabular event export suitable for Excel or SIEM ingestion.

- **HTML Dashboard** (signins_intel_<user>_<days>d_<timestamp>.html): Standalone interactive report featuring:

- **Summary** stat cards (Total Logs, Success, Failures, Malicious IPs, Suspicious IPs).

	- Multi-field live search (filters by IP, app, browser, error reason, or attack type).

	- Instant filter buttons for authentication status and IP threat levels.

	- Visual risk score bars and attack category badges.