# ENTERPRISE SECURITY LOG DATASET — SCHEMA DOCUMENTATION

December 2025 | Living Off The Land Attack Campaign | ATK_29367

---

## OVERVIEW

This dataset contains **realistic enterprise security logs** with an embedded multi-stage APT attack campaign. Logs include:

- **Windows security events** (process execution, network connections, file operations, authentication)
- **Defense product logs** (EDR, DLP, SIEM, PAM, MFA) that react to suspicious activity
- **Service account background activity** (60+ service accounts generating continuous noise)
- **Ground truth labels** for every attack action

**Key characteristics:**
- 8.2M total logs spanning 25 days
- 491 attack logs (0.00006% signal)
- 219 defense alerts (44% detection rate)
- Attack hidden in realistic enterprise noise

---

## LOG TYPE CATEGORIES

Logs are categorized by `log_type` field:

### Windows Security Events
- `windows_security_event` — Standard Windows Event Log entries
- Generated for all user and service account activity
- **No vendor-specific fields**

### Defense Product Logs  
- `defender_atp_alert` — Microsoft Defender ATP alerts
- `dlp_alert` / `dlp_block` — Data Loss Prevention
- `siem_alert` — SIEM correlation events
- `pam_access_denied` — Privileged Access Management
- `mfa_challenge_failed` — Multi-Factor Authentication
- Plus 20+ other defense log types
- **Contain vendor-specific fields** (see Defense Fields section)

---

# CORE FIELDS (All Logs)

| Field           | Type   | Required    | Description                                   |
| --------------- | ------ | ----------- | --------------------------------------------- |
| timestamp       | string | yes         | ISO 8601: `"2025-12-21 14:32:01"`             |
| log_type        | string | yes         | Log source (see Log Type Categories above)    |
| user            | string | yes         | Human identity: `"thomas.davis147"` or `"NA"` |
| account         | string | yes         | Security principal (user or `svc_*`)          |
| service_account | boolean| yes         | `true` or `false`                             |
| hostname        | string | yes         | Device: `"WS-SEC-0148"`, `"DB-SRV-01"`        |
| device_type     | string | yes         | `workstation`, `database_server`, etc         |
| location        | string | yes         | `NYC_HQ`, `SF_Office`, `London`, `Remote_VPN` |
| department      | string | conditional | `Security`, `Finance`, `Engineering`, etc     |
| role            | string | conditional | `"Security Analyst"`, `"DBA"`, etc            |
| process_name    | string | conditional | `"powershell.exe"`, `"net.exe"`, etc          |
| parent_process  | string | conditional | `"cmd.exe"`, `"explorer.exe"`, etc            |
| command_line    | string | conditional | Full command with arguments                   |
| event_type      | string | yes         | `process_start`, `network_connection`, etc    |
| source_ip       | string | conditional | `"10.1.20.9"`                                 |
| destination_ip  | string | conditional | `"10.1.52.52"` or `"203.0.113.30"` (C2)       |
| port            | integer| conditional | `88`, `443`, `3389`, etc                      |
| protocol        | string | conditional | `TCP`, `UDP`, `HTTPS`, `RDP`, `Kerberos`, etc |
| session_id      | string | conditional | `"thomas.davis147_2025-12-21"`                |
| success         | boolean| conditional | `true` or `false` (for Windows events)        |
| error           | string | conditional | Error message if `success=false`              |
| event_id        | integer| conditional | Windows Event ID: `4688`, `4625`, `5156`, etc |

**Key Insight:** The `user` and `account` fields show **who is using what credentials**:
- `user=lisa.miller081, account=lisa.miller081` → User's direct activity
- `user=lisa.miller081, account=svc_backup` → User hijacked/using service account (lateral movement)
- `user=svc_database, account=svc_database` → Service account background activity

---

# DEFENSE & OBSERVABILITY FIELDS (Defense Logs Only)

These fields appear **only in defense product logs** (when `log_type` is NOT `windows_security_event`).

## Detection Core

| Field                | Type   | Required    | Description                                          |
| -------------------- | ------ | ----------- | ---------------------------------------------------- |
| severity             | string | yes         | `"low"`, `"medium"`, `"high"`, `"critical"`          |
| action_taken         | string | yes         | `"blocked"`, `"logged"`, `"quarantined"`, `"denied"` |
| alert_name           | string | yes         | Human-readable alert: `"Suspicious PowerShell Activity"` |
| alert_type           | string | conditional | `"threat"`, `"behavioral"`, `"policy"`, `"rule"`     |
| reason               | string | conditional | Why action taken: `"Malicious script pattern detected"` |
| confidence_level     | float  | conditional | 0.0–1.0 probability this is malicious                |
| detection_type       | string | conditional | `"Behavioral"`, `"Signature"`, `"Heuristic"`, `"Policy"` |

**Usage:**
- `alert_name` — Primary detection identifier (e.g., "Mimikatz Detected", "Credential Theft Attempt")
- `alert_type` — Category of detection
- `reason` — Technical explanation (e.g., "AMSI blocked suspicious script", "Certificate expired")
- `severity` — Risk level assigned by defense product
- `action_taken` — What the defense product did
- `detection_confidence` — ML/heuristic confidence score

## Target Information

| Field  | Type   | Required    | Description                                            |
| ------ | ------ | ----------- | ------------------------------------------------------ |
| target | string | conditional | What was targeted: `"lsass.exe"`, `"Credential Store"` |

**Usage:** Indicates the asset/resource that was targeted by suspicious activity.

## Vendor Information

| Field            | Type   | Required    | Description                                           |
| ---------------- | ------ | ----------- | ------------------------------------------------------|
| vendor           | string | conditional | Defense product vendor (e.g., `"Microsoft Defender"`) |
| investigation_id | int    | conditional | Microsoft Defender investigation ID                   |

**Usage:** Vendor-specific identifiers for correlation and investigation.

## Authentication & Access Control

| Field                  | Type   | Required    | Description                                     |
| ---------------------- | ------ | ----------- | ----------------------------------------------- |
| authentication_type    | string | conditional | `"Kerberos"`, `"NTLM"`, `"OAuth"`, `"Certificate"` |
| authentication_package | string | conditional | Technical auth mechanism (e.g., `"NTLM v2"`)    |
| policy_violated        | string | conditional | Specific policy name that was violated          |

**Usage:** 
- `authentication_type` — High-level auth method
- `authentication_package` — Low-level implementation details
- `policy_violated` — Name of DLP/PAM/access policy that blocked action

## Specialized Fields

| Field         | Type   | Required    | Description                                       |
| ------------- | ------ | ----------- | ------------------------------------------------- |
| destination   | string | conditional | Destination hostname/server (in addition to IP)   |
| file_operation| string | conditional | `"create"`, `"modify"`, `"delete"` (File Integrity Monitoring) |
| query_type    | string | conditional | `"A"`, `"MX"`, `"suspicious"` (DNS monitoring)    |
| database      | string | conditional | Database name for database monitoring events      |
| ticket_type   | string | conditional | `"TGT"`, `"TGS"` (Kerberos monitoring)            |
| http_status   | string | conditional | `"403 Forbidden"` (Proxy logs)                    |
| language_mode | string | conditional | `"ConstrainedLanguage"` (PowerShell logging)      |

**Usage:** Context-specific fields that appear in specialized monitoring scenarios.

---

# FILE HASH & REPUTATION FIELDS

These fields are present **only on events where hashing is performed** (e.g., `process_start`, `file_create`, `file_modify`, some `network_connection` events during exfiltration).

| Field            | Type    | Required    | Description                                                       |
| ---------------- | ------- | ----------- | ----------------------------------------------------------------- |
| sha256           | string  | conditional | 64-character SHA-256 file hash for the referenced file/executable |
| md5              | string  | conditional | 32-character MD5 file hash                                        |
| file_size        | integer | conditional | Estimated file size in bytes (realistic ranges by file type)      |
| file_path        | string  | conditional | Full file path (e.g., `"C:\\temp\\archive.zip"`)                  |
| signed           | boolean | conditional | `true` if the file is digitally signed, `false` otherwise         |
| prevalence_score | float   | conditional | Approximate prevalence of the hash in the enterprise (0.0–1.0)    |

**Intended semantics:**

* **sha256 / md5** — Deterministic hashes per file within a simulation run. Known Windows binaries reuse fixed hashes; attacker-created artifacts and many enterprise files get unique hashes.
* **file_size** — Realistically estimated based on file type (e.g., LSASS dumps large, scripts small, archives variable).
* **signed** — `true` / `false`. Benign enterprise files: ~60% signed. Malicious files: ~5% signed (stolen or abused certs).
* **prevalence_score** — Close to `1.0`: very common (e.g., `explorer.exe`). Moderate (0.1–0.5): "seen sometimes". Very low (0.00001–0.001): rare attacker artifacts.

---

# ATTACK LABELS (GROUND TRUTH)

| Field        | Type   | Required | Description                                  |
| ------------ | ------ | -------- | -------------------------------------------- |
| attack_id    | string | yes      | `"ATK_29367"` or `null`                      |
| attack_type  | string | yes      | MITRE technique: `"t1059.001"` or `null`     |
| stage_number | string | yes      | `"0"`–`"15"` for kill chain stage, or `null` |

**Benign events:** all attack_* fields are `null`  
**Attack events:** all attack_* fields populated

**Kill Chain Mapping (ATK_29367):**
- Stages 0–3: t1059.001 (PowerShell execution)
- Stages 4–6: t1087.002 (Domain Account Discovery)
- Stages 7–10: t1021.001 (RDP Lateral Movement)
- Stages 11–15: t1041 (Exfiltration)

**Account progression:**
- All stages → `user = "lisa.miller081"`
- Stages 0–6 → `account = "lisa.miller081"` (direct activity)
- Stages 7+ → `account = "svc_backup"`, `"svc_crm_integration"` (service account hijacking for lateral movement and exfil)

---

# EVENT TYPES

**Windows Security Events:**
- `process_start`, `process_end`
- `file_access`, `file_create`, `file_delete`, `file_modify`
- `network_connection`
- `admin_action`, `privilege_escalation`
- `login_success`, `login_failure`, `logout`
- `kerberos_service_ticket_success`, `kerberos_service_ticket_failure`
- `kerberos_auth_success`, `kerberos_auth_failure`
- `registry_access`, `scheduled_task`, `service_start`
- `database_query`, `web_browsing`, `email_access`
- `usb_access`, `print_event`, `system_event`

**Defense Events:**
Defense logs use specialized event types but may also reference original Windows event types for context.

---

# LOG TYPE REFERENCE

## Windows Events
- `windows_security_event` — All benign and attack Windows logs

## EDR Products
- `defender_atp_alert` — Microsoft Defender ATP alerts
- `defender_atp_detection` — Defender blocks/quarantines

## Endpoint Protection
- `amsi_detection` — Anti-Malware Scan Interface blocks
- `applocker_block` — AppLocker application control
- `wdac_block` — Windows Defender Application Control
- `execution_policy_block` — PowerShell execution policy

## Identity & Authentication
- `mfa_challenge_failed` — Multi-Factor Authentication failures
- `kerberos_authentication_event` — Kerberos monitoring (observability)
- `kerberos_attack_detected` — Kerberoasting detection
- `ntlm_authentication_event` — NTLM monitoring
- `pam_access_denied` — Privileged Access Management denials
- `credential_access_alert` — Credential theft detection

## Network Security
- `proxy_block` — Web proxy filtering
- `ssl_inspection_alert` — SSL inspection findings
- `firewall_block` — Network firewall blocks
- `lateral_movement_alert` — Lateral movement detection
- `dns_query_alert` — DNS monitoring
- `smb_traffic_alert` — SMB protocol monitoring

## Data Protection
- `dlp_alert` — Data Loss Prevention alerts
- `dlp_block` — DLP blocks
- `file_integrity_alert` — File Integrity Monitoring

## Detection Systems
- `behavioral_detection_alert` — Behavioral analytics
- `siem_alert` — SIEM correlation
- `suspicious_command_line_detected` — Process monitoring

## Other
- `memory_protection_block` — Memory protection (e.g., Credential Guard)
- `nac_quarantine` — Network Access Control quarantine
- `access_control_event` — Generic access denials
- `database_query_alert` — Database activity monitoring

---

# MITRE ATT&CK TECHNIQUE REFERENCE

**t1059.001 — Command and Scripting Interpreter: PowerShell**
- Tactic: Execution
- Used in stages 0–3 (initial access, malicious script execution)
- https://attack.mitre.org/techniques/T1059/001/

**t1087.002 — Account Discovery: Domain Account**
- Tactic: Discovery
- Used in stages 4–6 (domain admin enumeration, AD reconnaissance)
- https://attack.mitre.org/techniques/T1087/002/

**t1021.001 — Remote Services: Remote Desktop Protocol**
- Tactic: Lateral Movement
- Used in stages 7–10 (RDP to application servers)
- https://attack.mitre.org/techniques/T1021/001/

**t1041 — Exfiltration Over C2 Channel**
- Tactic: Exfiltration
- Used in stages 11–15 (multi-channel data exfiltration)
- https://attack.mitre.org/techniques/T1041/

---

# EXAMPLE LOGS

## Example 1: Benign User Event — Process Start (Windows)


```json
{
  "event_type": "process_start",
  "user": "lisa.miller081",
  "hostname": "WS-SEC-0082",
  "process_name": "teams.exe",
  "command_line": "Starting teams.exe",
  "source_ip": "10.1.151.56",
  "department": "Security",
  "location": "SF_Office",
  "device_type": "workstation",
  "success": true,
  "session_id": "lisa.miller081_2026-01-07",
  "service_account": false,
  "account": "lisa.miller081",
  "port": 0,
  "event_id": 5156,
  "parent_process": "",
  "signed": false,
  "log_type": "windows_security_event",
  "timestamp": "2026-01-07 08:50:00"
}
```

**Key:** Normal benign activity - Security analyst starting Teams. No attack labels.

---

## Example 2: Benign User Event — Email Access (Windows)

```json
{
  "event_type": "email_access",
  "user": "lisa.miller081",
  "hostname": "WS-SEC-0082",
  "process_name": "outlook.exe",
  "command_line": "outlook.exe /select outlook:inbox",
  "source_ip": "10.1.148.148",
  "destination_ip": "10.1.50.15",
  "department": "Security",
  "location": "SF_Office",
  "device_type": "workstation",
  "success": true,
  "session_id": "lisa.miller081_2025-12-26",
  "service_account": false,
  "account": "lisa.miller081",
  "port": 993,
  "protocol": "IMAPS",
  "event_id": 4663,
  "parent_process": "",
  "error": "",
  "signed": false,
  "log_type": "windows_security_event",
  "timestamp": "2025-12-26 18:35:00"
}
```

**Key:** Benign email access. Normal Security department activity.

---

## Example 3: Legitimate User → Service Account Access (Windows)

```json
{
  "event_type": "kerberos_service_ticket_success",
  "user": "lisa.miller081",
  "hostname": "WS-SEC-0082",
  "command_line": "Request service ticket for AD Connect",
  "source_ip": "10.1.92.131",
  "destination_ip": "10.1.52.118",
  "department": "Security",
  "location": "SF_Office",
  "device_type": "workstation",
  "success": true,
  "session_id": "svc_adconnect_2026-01-09",
  "service_account": false,
  "account": "svc_adconnect",
  "port": 88,
  "protocol": "Kerberos",
  "event_id": 4769,
  "parent_process": "cmd.exe",
  "log_type": "windows_security_event",
  "timestamp": "2025-12-27 12:36:05"
}
```

**Key:** `user != account` shows legitimate service account usage. Security analyst using AD Connect service account for legitimate work. **No attack_id** - this is benign.

---

## Example 4: Attack Event — PowerShell Execution (Windows)

```json
{
  "event_type": "admin_action",
  "user": "lisa.miller081",
  "hostname": "WS-SEC-0082",
  "process_name": "powershell.exe",
  "command_line": "Get-WmiObject Win32_ComputerSystem | Select-Object Domain,DomainRole",
  "source_ip": "10.2.161.12",
  "department": "Security",
  "location": "SF_Office",
  "device_type": "workstation",
  "success": true,
  "session_id": "ongoing_attack_ATK_29367_2025-12-22",
  "service_account": false,
  "account": "lisa.miller081",
  "protocol": "TCP",
  "event_id": 4672,
  "parent_process": "powershell.exe",
  "attack_id": "ATK_29367",
  "attack_type": "t1059.001",
  "stage_number": "3",
  "log_type": "windows_security_event",
  "timestamp": "2025-12-22 19:06:00"
}
```

**Key:** Attack stage 3 - PowerShell reconnaissance. Attacker querying domain information. All attack labels populated.

---

## Example 5: Attack Event — Domain Discovery (Windows)
(admin_action,lisa.miller081,WS-SEC-0082,whoami.exe,whoami,10.1.148.148,10.2.50.10,Security,SF_Office,workstation,true,ongoing_attack_ATK_29367_2025-12-23,false,lisa.miller081,null,null,null,null,windows_security_event,2025-12-23 00:43:05,2,TCP)

```json
{
  "event_type": "admin_action",
  "user": "lisa.miller081",
  "hostname": "WS-SEC-0082",
  "process_name": "whoami.exe",
  "command_line": "whoami",
  "source_ip": "10.1.148.148",
  "destination_ip": "10.2.50.10",
  "department": "Security",
  "location": "SF_Office",
  "device_type": "workstation",
  "success": true,
  "session_id": "ongoing_attack_ATK_29367_2025-12-23",
  "service_account": false,
  "account": "lisa.miller081",
  "protocol": "TCP",
  "event_id": 4672,
  "parent_process": "cmd.exe",
  "attack_id": "ATK_29367",
  "attack_type": "t1059.001",
  "stage_number": "2",
  "log_type": "windows_security_event",
  "timestamp": "2025-12-23 00:43:05"
}
```

**Key:** Attack stage 2 - Domain discovery. Simple whoami command during reconnaissance phase.

---

## Example 6: Attack Event — Service Account Hijacking (Windows)

```json
{
  "event_type": "kerberos_service_ticket_success",
  "user": "lisa.miller081",
  "hostname": "WS-SEC-0082",
  "process_name": "BackupExec.exe",
  "command_line": "Request service ticket for backup service",
  "source_ip": "10.1.151.56",
  "destination_ip": "10.2.50.6",
  "department": "Security",
  "location": "SF_Office",
  "device_type": "workstation",
  "success": true,
  "session_id": "svc_backup_2026-01-13",
  "service_account": false,
  "account": "svc_backup",
  "port": 88,
  "protocol": "Kerberos",
  "event_id": 4769,
  "parent_process": "services.exe",
  "attack_id": "ATK_29367",
  "attack_type": "t1041",
  "stage_number": "15",
  "log_type": "windows_security_event",
  "timestamp": "2026-01-13 04:56:02"
}
```

**Key:** Attack stage 14 - Service account hijacking. `user=lisa.miller081` but `account=svc_backup` shows attacker using stolen service account credentials. **Has attack_id** - this is malicious lateral movement.

---

## Example 7: Attack Event — RDP Lateral Movement with Failure (Windows)

```json
{
  "event_type": "network_connection",
  "user": "lisa.miller081",
  "hostname": "WS-SEC-0082",
  "process_name": "powershell.exe",
  "command_line": "Test-WSMan -ComputerName APP-SRV-03",
  "source_ip": "10.1.92.131",
  "destination_ip": "10.2.50.60",
  "department": "Security",
  "location": "SF_Office",
  "device_type": "workstation",
  "success": false,
  "session_id": "ongoing_attack_ATK_29367_2025-12-29",
  "service_account": false,
  "account": "lisa.miller081",
  "protocol": "WinRM",
  "event_id": 5156,
  "parent_process": "powershell.exe",
  "error": "Test-WSMan : Access is denied.",
  "attack_id": "ATK_29367",
  "attack_type": "t1021.001",
  "stage_number": "7",
  "log_type": "windows_security_event",
  "timestamp": "2025-12-28 22:23:01"
}
```

**Key:** Attack stage 7 - RDP lateral movement attempt. Failed connection (`success=false`, error message present). Shows realistic attacker trial-and-error.

---

## Example 8: Attack Event — Exfiltration Preparation (Windows)

```json
{
  "event_type": "admin_action",
  "user": "lisa.miller081",
  "hostname": "WS-SEC-0082",
  "process_name": "tasklist.exe",
  "command_line": "tasklist",
  "source_ip": "10.2.161.12",
  "department": "Security",
  "location": "SF_Office",
  "device_type": "workstation",
  "success": true,
  "session_id": "ongoing_attack_ATK_29367_2025-12-21",
  "service_account": false,
  "account": "lisa.miller081",
  "protocol": "TCP",
  "event_id": 4672,
  "parent_process": "cmd.exe",
  "attack_id": "ATK_29367",
  "attack_type": "t1041",
  "stage_number": "1",
  "log_type": "windows_security_event",
  "timestamp": "2025-12-21 13:20:04"
}
```

**Key:** Attack stage 14 - Exfiltration preparation. Attacker running tasklist during final exfil stage.

---

## Example 9: Defense Response — Defender ATP Alert (Defense Log)


```json
{
  "timestamp": "2025-12-23 01:51:05",
  "log_type": "defender_atp_alert",
  "account": "lisa.miller081",
  "alert_name": "Suspicious PowerShell Activity",
  "command_line": "Get-WmiObject Win32_ComputerSystem",
  "confidence_level": 0.75,
  "parent_process": "powershell.exe",
  "process_name": "powershell.exe",
  "severity": "medium",
  "vendor": "Microsoft Defender",
  "action_taken": "logged",
  "attack_id": "ATK_29367",
  "stage_number": "3"
}
```

**Key:** Defense log triggered by attack stage 3. Shows EDR detected suspicious PowerShell with 82% confidence. `action_taken="logged"` means not blocked, just alerted.

---

## Example 10: Defense Response — DLP Alert (Defense Log)

```json
{
  "timestamp": "2026-01-07 02:23:00",
  "log_type": "dlp_alert",
  "account": "svc_backup",
  "destination_ip": "203.0.113.30",
  "port": 8443,
  "alert_name": "Compressed Archive Upload Detected",
  "severity": "high",
  "action_taken": "logged",
  "reason": "Sensitive File Type",
  "attack_id": "ATK_29367",
  "stage_number": "12"
}
```

**Key:** DLP Alert on exfiltration attempt to external C2 (203.0.113.30) through svc_backup. Shows `alert_name` and `action_taken="logged"`. Defense successfully prevented this stage 13 action.

---

# KEY NOTES

## String Formatting
- Booleans stored as native JSON booleans (`true` / `false`)
- Stage numbers stored as strings (`"0"`, `"1"`, …)
- Null values use JSON `null`
- Empty strings represented as `""`

## Defense Log Behavior
- Defense logs are **generated AFTER attacks occur** (no precognition)
- Detection rate varies by attacker skill level (intermediate = 45% in this dataset)
- Multiple defense products may trigger on same attack action
- Defense logs reference the **original Windows log** via matching timestamp/command_line

## Lateral Movement Detection
The critical pattern: **`user != account`**
- `user=lisa.miller081, account=svc_crm_integration` with no attack_id → **Legitimate** (Security analyst using service account for work)
- `user=lisa.miller081, account=svc_backup` with `attack_id="ATK_29367"` → **Malicious** (attacker hijacked service account)
- Detection requires: Context (what command?), baseline (normal for this user?), sequence (what happened before?)

## Hashing Behavior
Hash fields (`sha256`, `md5`, `file_size`, `signed`, `prevalence_score`) appear only when the simulated EDR "decides" to hash the file (e.g., process execution, file_create, file_modify, selected file_access, malicious network exfil events). Many benign events will **not** have hash fields present.

## Network Patterns
- Internal addresses: `10.x.x.x` (enterprise network)
- External C2: `203.0.113.30`, `203.0.113.40` (ports 8443, 443)

## Common Service Accounts
- `svc_backup` — Backup operations (hijacked during ATK_29367 for exfiltration)
- `svc_adconnect` — AD sync (hijacked during ATK_29367 for lateral movement)
- `svc_database` — Database operations
- `svc_edr_agent` — EDR monitoring (generates most background logs)
- `svc_siem_collector` — Log collection
- `svc_monitoring` — Infrastructure monitoring
- Plus 50+ other service accounts

## Departments
Security, Engineering, Finance, Sales, HR, Legal, Operations, Support, IT, Marketing

## Locations
- NYC_HQ (10.1.0.0/16)
- SF_Office (10.2.0.0/16)
- London (10.3.0.0/16)
- Remote_VPN (192.168.0.0/16)

---

# DETECTION CHALLENGES

This dataset demonstrates several realistic detection challenges:

## 1. Tool Overlap
Security analysts legitimately use the same tools as attackers:
- PowerShell, net.exe, whoami.exe, tasklist.exe, dsquery.exe
- Process name alone = insufficient for detection
- lisa.miller081 is a Security Analyst - his benign work overlaps with attack tools

## 2. Service Account Noise
- Service accounts generate millions of logs
- Finding malicious service account use requires context and baselines
- `user != account` pattern appears in both benign and malicious logs

## 3. Legitimate Lateral Movement
- Security analysts legitimately access service accounts (svc_adconnect for AD work)
- Attacker access looks identical in raw logs
- Requires behavioral analysis to distinguish

## 4. Multi-Week Timeline
- 24-day campaign (Dec 21 - Jan 13) avoids spike detection
- 1-3 actions per day blends with normal activity
- Gradual progression from reconnaissance to exfiltration

## 5. Defense Product Limitations
- 44% detection rate (intermediate attacker)
- Some techniques evade all defenses
- Multiple products needed for coverage
- False negatives during lateral movement stages

---

# DATA QUALITY NOTES

## Realism Features
- Service accounts dominate logs (60-70% of all events)  
- Office apps used realistically (not every action logged)  
- Authentication events generate noise (Kerberos tickets, session establishment)  
- Defense products trigger probabilistically (not 100% detection)  
- Errors are realistic Windows errors (Access denied, network failures)  
- Multi-week attack timeline matches APT behavior  
- Attacker from Security department creates tool overlap challenge

## Scope
- Fully synthetic (no real user PII or company data)
- Single attack chain (living_off_land_basic)
- One attacker (lisa.miller081, Security Analyst)
- One skill level (intermediate attacker)
- One EDR vendor (Microsoft Defender ATP)
- Single defense configuration (Microsoft-based enterprise stack)
- Attack progresses from PowerShell → Domain Discovery → RDP Lateral Movement → Exfiltration

---