# ENTERPRISE SECURITY LOG DATASET — SCHEMA DOCUMENTATION

December 2025 | Living Off The Land Attack Campaign

---

## OVERVIEW

This dataset contains **realistic enterprise security logs** with an embedded multi-stage APT attack campaign. Logs include:

- **Windows security events** (process execution, network connections, file operations, authentication)
- **Defense product logs** (EDR, DLP, SIEM, PAM, MFA) that react to suspicious activity
- **Service account background activity** (60+ service accounts generating continuous noise)
- **Ground truth labels** for every attack action

**Key characteristics:**
- 8.1M total logs spanning 25 days
- 570 attack logs (0.007% signal)
- 209 defense alerts (37% detection rate)
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
- `crowdstrike_telemetry` — CrowdStrike Falcon observability
- `sentinelone_detection` — SentinelOne behavioral detections
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
| timestamp       | string | yes         | ISO 8601: `"2025-12-16 14:32:01"`             |
| log_type        | string | yes         | Log source (see Log Type Categories above)    |
| user            | string | yes         | Human identity: `"joseph.wilson475"` or `"NA"`|
| account         | string | yes         | Security principal (user or `svc_*`)          |
| service_account | string | yes         | `"true"` or `"false"`                         |
| hostname        | string | yes         | Device: `"WS-SEC-0476"`, `"DB-SRV-01"`        |
| device_type     | string | yes         | `workstation`, `database_server`, etc         |
| location        | string | yes         | `NYC_HQ`, `SF_Office`, `London`, `Remote_VPN` |
| department      | string | conditional | `Security`, `Finance`, `Engineering`, etc     |
| role            | string | conditional | `"Security Analyst"`, `"DBA"`, etc            |
| process_name    | string | conditional | `"powershell.exe"`, `"net.exe"`, etc          |
| parent_process  | string | conditional | `"cmd.exe"`, `"explorer.exe"`, etc            |
| command_line    | string | conditional | Full command with arguments                   |
| event_type      | string | yes         | `process_start`, `network_connection`, etc    |
| source_ip       | string | conditional | `"10.1.0.148"`                                |
| destination_ip  | string | conditional | `"10.1.52.52"` or `"203.0.113.70"` (C2)       |
| port            | string | conditional | `"135"`, `"443"`, `"3389"`, etc               |
| protocol        | string | conditional | `TCP`, `UDP`, `HTTPS`, `RDP`, etc             |
| session_id      | string | conditional | `"joseph.wilson475_2025-12-16"`               |
| success         | string | conditional | `"true"` or `"false"` (for Windows events)    |
| error           | string | conditional | Error message if `success="false"`            |

**Key Insight:** The `user` and `account` fields show **who is using what credentials**:
- `user=joseph.wilson475, account=joseph.wilson475` → User's direct activity
- `user=joseph.wilson475, account=svc_database` → User hijacked/using service account (lateral movement)
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
| detection_confidence | float  | conditional | 0.0–1.0 probability this is malicious                |
| detection_type       | string | conditional | `"Behavioral"`, `"Signature"`, `"Heuristic"`, `"Policy"` |

**Usage:**
- `alert_name` — Primary detection identifier (e.g., "Mimikatz Detected", "Credential Theft Attempt")
- `alert_type` — Category of detection
- `reason` — Technical explanation (e.g., "AMSI blocked suspicious script", "Certificate expired")
- `severity` — Risk level assigned by defense product
- `action_taken` — What the defense product did
- `detection_confidence` — ML/heuristic confidence score

## Target Information

| Field  | Type   | Required    | Description                                          |
| ------ | ------ | ----------- | ---------------------------------------------------- |
| target | string | conditional | What was targeted: `"lsass.exe"`, `"Credential Store"` |

**Usage:** Indicates the asset/resource that was targeted by suspicious activity.

## Vendor Information

| Field            | Type   | Required    | Description                                    |
| ---------------- | ------ | ----------- | ---------------------------------------------- |
| vendor           | string | conditional | `"CrowdStrike"`, `"Microsoft Defender"`, etc   |
| sensor_id        | int    | conditional | CrowdStrike sensor identifier                  |
| investigation_id | int    | conditional | Microsoft Defender investigation ID            |
| storyline_id     | string | conditional | SentinelOne storyline (attack chain) ID        |
| reputation_score | int    | conditional | Carbon Black file reputation (0-100)           |

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
| signed           | string  | conditional | `"true"` if the file is digitally signed, `"false"` otherwise     |
| prevalence_score | float   | conditional | Approximate prevalence of the hash in the enterprise (0.0–1.0)    |

**Intended semantics:**

* **sha256 / md5** — Deterministic hashes per file within a simulation run. Known Windows binaries reuse fixed hashes; attacker-created artifacts and many enterprise files get unique hashes.
* **file_size** — Realistically estimated based on file type (e.g., LSASS dumps large, scripts small, archives variable).
* **signed** — Represented as `"true"` / `"false"` in the dataset. Benign enterprise files: ~60% signed. Malicious files: ~5% signed (stolen or abused certs).
* **prevalence_score** — Close to `1.0`: very common (e.g., `explorer.exe`). Moderate (0.1–0.5): "seen sometimes". Very low (0.00001–0.001): rare attacker artifacts.

---

# ATTACK LABELS (GROUND TRUTH)

| Field        | Type   | Required | Description                                  |
| ------------ | ------ | -------- | -------------------------------------------- |
| attack_id    | string | yes      | `"ATK_84073"` or `null`                      |
| attack_type  | string | yes      | MITRE technique: `"t1059.001"` or `null`     |
| stage_number | string | yes      | `"0"`–`"15"` for kill chain stage, or `null` |

**Benign events:** all attack_* fields are `null`  
**Attack events:** all attack_* fields populated

**Kill Chain Mapping (ATK_84073):**
- Stages 0–3: t1059.001 (PowerShell execution)
- Stages 4–6: t1087.002 (Domain Account Discovery)
- Stages 7–10: t1021.001 (RDP Lateral Movement)
- Stages 11–15: t1041 (Exfiltration)

**Account progression:**
- Stages 0–1 → `account = "joseph.wilson475"`
- Stages 2+ → `account = "svc_database"`, `"svc_backup"`, `"svc_adconnect"` (service account hijacking)

---

# EVENT TYPES

**Windows Security Events:**
- `process_start`, `process_end`
- `file_access`, `file_create`, `file_delete`, `file_modify`
- `network_connection`
- `admin_action`, `privilege_escalation`
- `login_success`, `login_failure`, `logout`
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
- `crowdstrike_telemetry` — CrowdStrike observability
- `crowdstrike_detection` — CrowdStrike blocks
- `sentinelone_deep_visibility` — SentinelOne observability
- `sentinelone_detection` — SentinelOne blocks
- `carbonblack_event` — Carbon Black observability
- `carbonblack_detection` — Carbon Black blocks

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
- Used in stages 7–10 (RDP to domain controllers)
- https://attack.mitre.org/techniques/T1021/001/

**t1041 — Exfiltration Over C2 Channel**
- Tactic: Exfiltration
- Used in stages 11–15 (multi-channel data exfiltration)
- https://attack.mitre.org/techniques/T1041/

---

# EXAMPLE LOGS

## Example 1: Benign User Event (Windows)

```json
{
  "timestamp": "2025-12-16 09:15:23",
  "log_type": "windows_security_event",
  "user": "richard.miller061",
  "account": "richard.miller061",
  "service_account": "false",
  "hostname": "WS-SEC-0042",
  "device_type": "workstation",
  "location": "NYC_HQ",
  "department": "Security",
  "process_name": "excel.exe",
  "event_type": "process_start",
  "success": "true",
  "attack_id": null,
  "attack_type": null,
  "stage_number": null
}
```

## Example 2: Service Account Background Activity (Windows)

```json
{
  "timestamp": "2025-12-16 02:30:15",
  "log_type": "windows_security_event",
  "user": "NA",
  "account": "svc_backup",
  "service_account": "true",
  "hostname": "BACKUP-SRV-01",
  "device_type": "backup_server",
  "process_name": "robocopy.exe",
  "parent_process": "services.exe",
  "event_type": "file_create",
  "success": "true",
  "attack_id": null,
  "attack_type": null,
  "stage_number": null
}
```

## Example 3: Legitimate User → Service Account Access (Windows)

```json
{
  "timestamp": "2025-12-16 10:30:00",
  "log_type": "windows_security_event",
  "user": "linda.williams097",
  "account": "svc_database",
  "service_account": "false",
  "hostname": "WS-FIN-0123",
  "device_type": "workstation",
  "department": "Finance",
  "process_name": "tableau.exe",
  "command_line": "Starting tableau.exe",
  "event_type": "database_query",
  "destination_ip": "10.1.50.234",
  "success": "true",
  "attack_id": null,
  "attack_type": null,
  "stage_number": null
}
```

**Key:** `user != account` shows legitimate lateral movement (Finance user accessing database via service account).

## Example 4: Attack Event — Initial PowerShell Execution (Windows)

```json
{
  "timestamp": "2025-12-16 01:32:03",
  "log_type": "windows_security_event",
  "user": "joseph.wilson475",
  "account": "joseph.wilson475",
  "service_account": "false",
  "hostname": "WS-SEC-0476",
  "device_type": "workstation",
  "location": "SF_Office",
  "department": "Security",
  "process_name": "powershell.exe",
  "parent_process": "cmd.exe",
  "command_line": "powershell -ExecutionPolicy Bypass -Command \"Get-ExecutionPolicy\"",
  "event_type": "process_start",
  "source_ip": "192.168.207.82",
  "destination_ip": "10.1.50.20",
  "port": "88",
  "protocol": "Kerberos",
  "success": "false",
  "error": "Access is denied.",
  "attack_id": "ATK_84073",
  "attack_type": "t1059.001",
  "stage_number": "0"
}
```

## Example 5: Defense Response — AMSI Detection (Defense Log)

```json
{
  "timestamp": "2025-12-16 01:32:03",
  "log_type": "amsi_detection",
  "account": "joseph.wilson475",
  "process_name": "powershell.exe",
  "command_line": "powershell -executionpolicy bypass -command \"get-executionpolicy\"",
  "action_taken": "blocked",
  "severity": "high",
  "reason": "Access is denied.",
  "attack_id": "ATK_84073",
  "stage_number": "0"
}
```

**Key:** Defense log triggered by the attack — shows `action_taken="blocked"` and `severity="high"`.

## Example 6: Defense Response — Defender ATP Alert (Defense Log)

```json
{
  "timestamp": "2025-12-16 03:41:00",
  "log_type": "defender_atp_alert",
  "account": "joseph.wilson475",
  "alert_name": "Suspicious PowerShell Activity",
  "command_line": "get-host",
  "detection_confidence": 0.77,
  "parent_process": "powershell.exe",
  "process_name": "powershell.exe",
  "severity": "medium",
  "vendor": "Microsoft Defender",
  "investigation_id": 92629,
  "action_taken": "logged",
  "attack_id": "ATK_84073",
  "stage_number": "1"
}
```

**Key:** EDR alert with `detection_confidence` and vendor-specific `investigation_id`.

## Example 7: Defense Response — DLP Block (Defense Log)

```json
{
  "timestamp": "2025-12-16 01:51:03",
  "log_type": "dlp_block",
  "account": "joseph.wilson475",
  "destination_ip": "10.1.50.20",
  "policy_violated": "Prevent Data Exfiltration",
  "severity": "critical",
  "action_taken": "blocked",
  "attack_id": "ATK_84073",
  "stage_number": "0"
}
```

**Key:** DLP blocked network connection, shows `policy_violated` field.

## Example 8: Attack Event — Service Account Hijacking (Windows)

```json
{
  "timestamp": "2026-01-02 06:15:00",
  "log_type": "windows_security_event",
  "user": "joseph.wilson475",
  "account": "svc_database",
  "service_account": "false",
  "hostname": "DB-SRV-01",
  "device_type": "database_server",
  "process_name": "powershell.exe",
  "command_line": "Enter-PSSession -ComputerName APP-SRV-01 -Credential $cred",
  "event_type": "network_connection",
  "destination_ip": "10.1.50.123",
  "port": "5985",
  "protocol": "WinRM",
  "success": "true",
  "attack_id": "ATK_84073",
  "attack_type": "t1021.001",
  "stage_number": "9"
}
```

**Key:** `user=joseph.wilson475` but `account=svc_database` shows attacker hijacked service account for lateral movement.

## Example 9: Defense Response — PAM Denial (Defense Log)

```json
{
  "timestamp": "2025-12-18 01:34:01",
  "log_type": "pam_access_denied",
  "account": "svc_backup",
  "authentication_type": "Service Account Authentication",
  "destination_ip": "10.2.50.123",
  "reason": "Unauthorized service account access attempt",
  "severity": "high",
  "action_taken": "denied",
  "attack_id": "ATK_84073",
  "stage_number": "2"
}
```

**Key:** PAM blocked unauthorized service account use.

## Example 10: Exfiltration with File Hashing (Windows)

```json
{
  "timestamp": "2026-01-06 03:51:04",
  "log_type": "windows_security_event",
  "user": "joseph.wilson475",
  "account": "svc_database",
  "service_account": "false",
  "hostname": "DB-SRV-01",
  "device_type": "database_server",
  "process_name": "powershell.exe",
  "command_line": "Compress-Archive -Path C:\\SQLBackups\\*.bak -DestinationPath C:\\temp\\data.zip",
  "event_type": "file_create",
  "file_path": "C:\\temp\\data.zip",
  "sha256": "a1b2c3d4e5f6...",
  "md5": "9f8e7d6c5b4a...",
  "file_size": 524288000,
  "signed": "false",
  "prevalence_score": 0.00001,
  "success": "true",
  "attack_id": "ATK_84073",
  "attack_type": "t1041",
  "stage_number": "12"
}
```

**Key:** Shows file hashing fields during exfiltration stage.

---

# KEY NOTES

## String Formatting
- Booleans stored as `"true"` / `"false"` (not JSON booleans)
- Stage numbers stored as strings (`"0"`, `"1"`, …)
- Null values use JSON `null`

## Defense Log Behavior
- Defense logs are **generated AFTER attacks occur** (no precognition)
- Detection rate varies by attacker skill level (intermediate = 37% in this dataset)
- Multiple defense products may trigger on same attack action
- Defense logs reference the **original Windows log** via matching timestamp/command_line

## Lateral Movement Detection
The critical pattern: **`user != account`**
- `user=linda.williams097, account=svc_database` → **Legitimate** (Finance user running Tableau)
- `user=joseph.wilson475, account=svc_database` with `attack_id` → **Malicious** (attacker hijacked service account)
- Detection requires: Context (what command?), baseline (normal for this user?), sequence (what happened before?)

## Hashing Behavior
Hash fields (`sha256`, `md5`, `file_size`, `signed`, `prevalence_score`) appear only when the simulated EDR "decides" to hash the file (e.g., process execution, file_create, file_modify, selected file_access, malicious network exfil events). Many benign events will **not** have hash fields present.

## Network Patterns
- Internal addresses: `10.x.x.x`, `192.168.x.x`
- External C2: `203.0.113.70` (ports 8080, 443, 9090)

## Common Service Accounts
- `svc_database` — Database operations (hijacked during ATK_84073)
- `svc_backup` — Backup operations (hijacked during ATK_84073)
- `svc_adconnect` — AD sync (hijacked during ATK_84073)
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
- PowerShell, net.exe, whoami.exe, tasklist.exe
- nmap, Wireshark, Metasploit
- Process name alone = insufficient for detection

## 2. Service Account Noise
- svc_database generates 185K logs (64 attack logs = 0.03% signal)
- Finding malicious service account use requires context and baselines

## 3. Legitimate Lateral Movement
- Finance users access svc_database (Tableau, Excel reports)
- IT admins access svc_database (maintenance)
- Attacker access looks identical in raw logs

## 4. Multi-Week Timeline
- 23-day campaign avoids spike detection
- 1-3 actions per day blends with normal activity

## 5. Defense Product Limitations
- 37% detection rate (intermediate attacker)
- Some techniques evade all defenses
- Multiple products needed for coverage

---

# DATA QUALITY NOTES

## Realism Features
Service accounts dominate logs (60-70% of all events)  
Office apps used realistically (not every save logged)  
Authentication events generate noise (Kerberos every 15 min)  
Defense products trigger probabilistically (not 100%)  
Errors are realistic Windows errors (90% generic, 10% specific)  
Multi-week attack timeline matches APT behavior  

## Limitations
- Fully synthetic (no real user PII or company data)
- Single attack chain (living_off_land_basic)
- One skill level (intermediate)
- One defense configuration (represents common enterprise stack)

---