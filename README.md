# Enterprise Attack Simulator

**AI-Powered Synthetic Security Log Dataset for Detection Engineering**

---

## What This Is

A **realistic enterprise security log dataset** featuring:
- **8+ million enterprise logs** with realistic background noise
- **Full APT attack campaign** spanning 24 days
- **55+ service accounts** with authentic activity patterns
- **500 users** across 10 departments with role-based behavior
- **Defense product logs** (EDR, DLP, SIEM, PAM, MFA) that react to attacks
- **Labeled ground truth** for every attack action

Built by an ML engineer working in cybersecurity who encountered a common challenge: limited access to realistic, labeled security data for training and testing detection systems.

---

## Table of Contents
- [Background & Motivation](#background--motivation)
- [Quick Start](#quick-start)
- [Attack Chain](#attack-chain-living_off_land_basic)
- [Why This Attack Is Hard to Detect](#why-this-attack-is-hard-to-detect)
- [Dataset Statistics](#dataset-statistics)
- [Schema Overview](#schema-overview)
- [How This Dataset Differs](#how-this-dataset-differs)
- [Dataset Scope](#dataset-scope)
- [Repository Contents](#repository-contents)
- [License & Attribution](#license--attribution)

---

## Background & Motivation

Security teams face a data challenge:

**Training detection systems** requires labeled attack data, but real breaches are rare, sensitive, and can't be freely shared. Most teams resort to:
- Static datasets from years ago (DARPA 2000, CICIDS)
- Lab exercises with clean, compressed attack scenarios
- Limited red team engagements that can't run continuously

**Validating detections** is difficult without realistic test data that mirrors actual enterprise environments—complete with background noise, service account activity, and the tool overlap that makes real attacks hard to detect.

**Practicing investigations** on simplified lab data doesn't prepare analysts for the challenges of finding attacks buried in millions of enterprise logs.

This dataset aims to address these gaps by providing:
- Realistic enterprise-scale logs (8M+ events)
- Labeled attack data embedded in normal activity
- Service account behavior and legitimate lateral movement
- Defense product responses (EDR, DLP, SIEM)
- Multi-week attack timelines

This is one approach to the training data problem—there are certainly others—and is offered as a research resource for the community.

---

## Sample Dataset Characteristics

### Living Off The Land Attack (Intermediate Skill)

**Attack Profile:**
- **Attacker:** thomas.davis147 (Security Analyst, blends with normal activity)
- **Campaign:** 24 days (Dec 21 - Jan 13, 2026)
- **Techniques:** PowerShell to Domain Discovery to RDP to Exfiltration
- **Service accounts hijacked:** svc_adconnect, svc_crm_integration

**Dataset Stats:**
- **Total windows security logs:** 8,036,577
- **Total defense logs:** 183,649
- **Attack logs:** 491 (0.00006% - realistic signal-to-noise)
- **Defense alerts (unique attack logs caught):** 219 (45% detection rate)
- **Users:** 500 across 10 departments
- **Service accounts:** 54 generating background activity
- **Timeline:** 25 days of continuous enterprise activity

**Attack Buried in Noise:**
```
thomas.davis147 (compromised user):
├─ Benign logs: 2,797 (83%)
└─ Attack logs: 491 (17%)

svc_backup (hijacked service account):
├─ Benign logs: 48130 (99.9%)
└─ Attack logs: 54 (0.001%)
```

**Defense Response:**
```
Defender ATP alerts: 153
credential_access_alert: 32
dlp_block: 31
suspicious_command_line_detected: 29
siem_alert: 23
dlp_alert: 15
```

---

## What Makes This Dataset Different

### 1. **Realistic Attack Timelines**
Not compressed lab scenarios, actual APT behavior:
- **Script kiddie:** 7 days (rapid, noisy)
- **Intermediate:** 21-35 days (patient, learning)
- **Advanced:** 60+ days (months-long dwell time)

This dataset: **24 days** (intermediate skill level)

### 2. **Service Account Realism**
54 service accounts generating millions of background logs:
```
svc_edr_agent: 968K logs (endpoint monitoring)
svc_siem_collector: 940K logs (log collection)
svc_crm_integration: 105K logs (includes 11 attack logs, 0.0001% signal)
svc_backup=: 48K logs (includes 54 attack logs,  .001% signal)
```

Attack logs are **buried in realistic enterprise noise** - just like real breaches.

### 3. **Defense Product Logs**
Unlike static datasets, this includes realistic defense responses:
- **Endpoint protection:** EDR alerts, blocks, and detections
- **Access control:** PAM denials, MFA challenges, NAC quarantine
- **Security monitoring:** SIEM correlation, behavioral detection
- **Network security:** DLP blocks, proxy filtering, lateral movement alerts

**Detection rate:** 45% (realistic for intermediate-skill attacker)

### 4. **Legitimate Lateral Movement**
Shows both legitimate and malicious service account usage:
- Finance users accessing databases (Tableau, PowerBI)
- IT admins performing maintenance
- Attackers hijacking service accounts

This is the **real detection challenge**: distinguishing malicious from legitimate.

---

## Potential Use Cases

This dataset was created with several use cases in mind:

### **Training ML Detection Models**
- Labeled ground truth for supervised learning
- Realistic signal-to-noise ratio (0.00008% attack signal)
- Service account and user behavior baselines
- Defense product logs as additional features

### **Validating Detection Logic**
- Test whether your rules detect this intermediate-skill attack
- Identify which stages evade defense detection
- Understand false positive rates in realistic noise

### **SOC Analyst Training**
- Practice investigating multi-week campaigns
- Learn to distinguish legitimate from malicious lateral movement
- Navigate enterprise-scale log volumes

### **Research & Education**
- Study APT behavior patterns over realistic timelines
- Analyze service account hijacking techniques
- Understand defense product effectiveness

**Note:** This is a **static dataset** generated from a simulation framework. The full simulation capability (custom defense configurations, different attack chains, varying skill levels) is part of ongoing research work. This dataset represents one specific scenario: a 24-day intermediate-skill living-off-the-land attack.

---

## Repository Contents

```
├── data/
│   ├── csv/
│   │   └── two_day_sample.csv.gz       # 26MB CSV sample (2 days, included)
│   └── json/
│       └── small_sample_security_department.json  # 48MB JSON sample (Security dept)
├── notebooks/
│   └── explore_dataset.ipynb           # Dataset analysis and examples
├── docs/
│   └── SCHEMA.md                       # Complete field documentation  
└── README.md
```

**Full Datasets (External):**
- **CSV Format (HuggingFace):** 231MB compressed, single file
- **JSON Format (HuggingFace):** 287MB compressed, 25 files by day

---

## Quick Start

### Option 1: Small Samples (Included in Repo)

**CSV Format (2-day sample):**
```bash
git clone https://github.com/gregdiy/cyber_simulation
cd cyber_simulation

# Load 2-day CSV sample
import pandas as pd
df = pd.read_csv('data/csv/two_day_sample.csv.gz')  # 26MB, pandas handles gzip

# Filter to attack logs
attack = df[df['attack_id'].notna()]
print(f"Attack logs: {len(attack)}")
```

**JSON Format (Security department sample):**
```python
import pandas as pd

# Load Security department sample (162K logs, pre-labeled)
df = pd.read_json('data/json/small_sample_security_department.json', lines=True)

# Already labeled as "benign" or "malicious"
print(df['label'].value_counts())

# Fields: account, user, department, process_name, command_line, timestamp,
#         protocol, source_ip, destination_ip, severity, log_type, 
#         attack_type, event_type, label
```

### Option 2: Full Dataset (8.1M logs, HuggingFace)

**CSV Format (single file):**
```bash
cd /path/to/cyber_simulation

mkdir -p data

#297 mb compressed
curl -L -o data/simulation.csv.gz \
   https://huggingface.co/datasets/gregalr/cyber_simulation/resolve/main/simulation.csv.gz

# Load in Python
import pandas as pd
df = pd.read_csv('data/simulation.csv.gz', sep="\t")  # Pandas handles gzip

```

**JSON Format (25 files by day):**
```bash
cd /path/to/cyber_simulation

mkdir -p data

# Download JSON format (split by day)
curl -L -o cyber_simulator_json_format.tar.gz \
  https://huggingface.co/datasets/gregalr/cyber_simulation_json_format/resolve/main/cyber_simulator_json_format.tar.gz

# Uncompress
tar -xzf cyber_simulator_json_format.tar.gz

# Results in: day_1.json, day_2.json, ..., day_25.json
```

**Load JSON by day:**
```python
import pandas as pd

# Load single day
df_day1 = pd.read_json('data/2025-12-21.json', lines=True)

# Or load all days
import glob
all_files = glob.glob('data/*.json')
df_full = pd.concat([pd.read_json(f, lines=True) for f in all_files], ignore_index=True)
```

---

## Schema Overview

### Core Fields
```
timestamp          - ISO 8601: "2025-12-21 01:32:03"
log_type           - "windows_security_event", "defender_atp_alert", etc.
user               - Human identity: "thomas.davis147"
account            - Security principal (user or svc_*)
hostname           - Device: "WS-SEC-0148", "DB-SRV-01"
device_type        - workstation, database_server, domain_controller
location           - NYC_HQ, SF_Office, London, Remote_VPN
department         - Security, Finance, Engineering, etc
```

### Activity Fields
```
process_name       - "powershell.exe", "net.exe"
command_line       - Full command with arguments
event_type         - process_start, network_connection, file_access
source_ip          - Internal: 10.x.x.x, VPN: 192.168.x.x
destination_ip     - Internal or external C2
port               - 135, 443, 3389, etc
protocol           - TCP, UDP, HTTPS, RDP
```

### Attack Labels
```
attack_id          - "ATK_29367" or null
attack_type        - "t1059.001" (MITRE technique) or null
stage_number       - "0" through "15" or null
```

### Defense Logs (30+ types)
```
log_type           - "defender_atp_alert", "dlp_block", "siem_alert"
severity           - low, medium, high, critical
action_taken       - blocked, logged, quarantined, denied
vendor             - Defende Product vendor
detection_confidence - 0.0-1.0
alert_name         - "Suspicious PowerShell Activity"
reason             - "Malicious script pattern detected"
```

See `docs/SCHEMA.md` for complete documentation including all defense fields.

---

## Attack Chain: living_off_land_basic

**Threat Actors:** APT29, Cozy Bear, The Dukes  
**Description:** PowerShell-based attack using legitimate tools  
**Flow:** PowerShell execution to Domain discovery to RDP lateral movement to Data exfiltration

### Stage Breakdown

**Stages 0-3: PowerShell Execution (t1059.001)**
```
Dec 21-23: Initial access and environment learning (144 logs)
- Get-ChildItem Env: | Where-Object {$_.Name -like '*PATH*'}
- reg query HKLM\SOFTWARE\Microsoft\PowerShell\1\ShellIds\Microsoft.PowerShell
- nltest /domain_trusts
- Get-WmiObject Win32_ComputerSystem | Select-Object Domain,DomainRole
- Test-NetConnection -ComputerName 203.0.113.40 -Port 443
- wmic process where name='powershell.exe' get ProcessId,CommandLine
- Attacker learns defense posture through trial-and-error
- Account: thomas.davis147 (Security Analyst - realistic tool overlap)
```

**Stages 4-6: Domain Discovery (t1087.002)**
```
Dec 22-26: Active Directory reconnaissance (91 logs)
- Get-ADUser -Filter * -Properties LastLogonDate | Select-Object Name,LastLogonDate
- net accounts /domain
- Get-ADGroupMember -Identity "Domain Admins" | Select-Object Name,SamAccountName
- dsquery user -limit 10, dsquery group -name "Domain Admins"
- net group "Domain Admins" /domain
- Get-Process lsass | Select-Object Id,Name,WorkingSet
- Identifies high-value targets and domain structure
- Enumerates domain admins and service accounts
- Account: thomas.davis147
```

**Stages 7-10: Lateral Movement (t1021.001)**
```
Dec 28 - Jan 2: RDP lateral movement to servers (96 logs)
- ping APP-SRV-03
- Test-WSMan -ComputerName APP-SRV-03
- reg query HKCU\Software\Microsoft\Terminal Server Client\Servers
- Get-NetTCPConnection -RemotePort 3389 -State Established
- cmdkey /list
- tasklist /v /fi "imagename eq rdpclip.exe"
- Get-Process -Name rdpclip | Select Id,Name,StartTime
- Spreads to application servers using RDP
- Account: thomas.davis147
```

**Stages 11-15: Exfiltration (t1041)**
```
Jan 5-13: Data collection and exfiltration (160 logs)
- dir C:\temp\archive.zip
- Get-ItemProperty C:\temp\archive.zip | Select-Object Length
- Test-NetConnection 203.0.113.30 -Port 8443
- nslookup 203.0.113.30
- Get-NetTCPConnection -State Established | Select-Object LocalAddress,RemoteAddress,RemotePort
- netstat -ano | findstr :8443
- Get-ChildItem C:\temp -Filter *.zip
- wevtutil qe Security /c:10 /rd:true /f:text (covering tracks)
- Stages data in C:\temp, tests exfil connection, monitors network state
- Account: thomas.davis147
```

---

## Why This Attack Is Hard to Detect

1. **Security analyst tools overlap with attacker tools**  
   PowerShell, net.exe, RDP - all used legitimately by Security dept

2. **Service account activity provides perfect cover**  
   svc_backup generates 48K logs - 51 attack logs blend in (0.04%)

3. **Multi-week dwell time avoids spike detection**  
   24-day campaign - no sudden anomaly, gradual progression

4. **Legitimate credentials bypass many controls**  
   Hijacked service accounts have authorized access

5. **Living-off-land techniques**  
   No malware, only built-in Windows tools

---

## Dataset Statistics

```
Total logs:           8,220,226
Window Security Logs: 8,036,577
Defense Logs:         183,649
Attack logs:          491 (0.00006%)
Defense alerts:       219 (45% detection rate)
Users:                500
Service accounts:     54
Devices:              1,024
Locations:            4 (NYC, SF, London, Remote VPN)
Duration:             25 days
Attack stages:        16
MITRE techniques:     4
```

---

## How This Dataset Differs

This dataset was created to address a specific gap: **realistic, labeled training data at enterprise scale**. Here's how it compares to other common resources:

### Static Attack Datasets
Examples: DARPA 2000, CICIDS, KDD Cup

**Similarities:** Labeled ground truth, repeatable scenarios  
**Differences:** Multi-week timelines, service account noise, defense product logs  
**Tradeoff:** Single attack scenario vs. diverse attack types  

### Live Testing Platforms
Examples: Commercial breach & attack simulation platforms

**Different purpose:** Those validate deployed controls; this provides training data  
**Complementary:** Use those to test, use this to train  
**Tradeoff:** Not testing real systems, purely synthetic  

### Interactive Training Environments
Examples: Cyber ranges, virtual labs, CTF platforms

**Similarities:** Controlled, repeatable scenarios  
**Differences:** Enterprise-scale noise (8M logs), realistic service account activity  
**Tradeoff:** Can't interact with attack in real-time  

### Real Breach Data

**Nothing replaces this:** Real incidents provide ground truth  
**This is useful when:** Real data is unavailable, sensitive, or can't be shared  
**Tradeoff:** Synthetic doesn't capture all real-world complexity  

---

**Bottom line:** This dataset is not a replacement for any of these—it's another tool in the toolkit, useful when you need labeled, repeatable, shareable data at enterprise scale.

---

## Dataset Scope

This release focuses on one well-developed scenario to provide depth and realism:

**Attack Profile:**
- Campaign: 24-day living-off-the-land attack
- Skill level: Intermediate (realistic failure rates, learning behavior)
- Environment: Enterprise on-premises (Active Directory, Windows)
- Scale: 8.1M logs across 500 users and 54 service accounts

**Defense Configuration:**
- EDR: Microsoft Defender ATP
- Access control: PAM, MFA, NAC
- Network security: DLP, proxy filtering
- Monitoring: SIEM correlation, behavioral detection
- Detection rate: 45% (realistic for this attacker skill level)

**Design Choice:**
We focused on one scenario executed at high fidelity rather than many scenarios with less depth. This allows for detailed analysis of attack progression, defense response patterns, and the challenges of detecting sophisticated attacks in realistic enterprise noise.

The dataset is static and synthetic, representing a single attack campaign. This makes it repeatable, shareable, and suitable for training and research.

---

## Why Realistic Timelines Matter

**Compressed approach (most datasets):**
```
Hour 1: Initial access
Hour 2: Lateral movement
Hour 3: Exfiltration
→ Unrealistic, easy to detect
```

**Realistic approach (this dataset):**
```
Week 1: Initial access (learning defenses)
Week 2: Reconnaissance (patient enumeration)
Week 3: Lateral movement (slow pivot)
Week 4: Exfiltration (final push)
→ Mirrors real APT behavior
```

**Real-world validation:**
- Mandiant M-Trends: Average dwell time 16-21 days (intermediate attackers)
- FireEye: Advanced attackers  60-90 days
- This dataset: 24 days for intermediate = realistic

---

## License & Attribution

**For Research & Education:** Free to use  
**For Commercial Use:** Contact for licensing

**Project:** Phantom Armor - Enterprise Attack Simulator  
**Author:** Greg Rothman  
**Contact:** gregralr@phantomarmor.com  

**Note:** All data is fully synthetic. No real users, systems, or organizations are represented.

---

## Citation

If you use this dataset in your research, please cite:

```bibtex
@dataset{phantom_armor_2025,
  author = {Rothman, Greg},
  title = {Enterprise Attack Simulator: AI-Powered Synthetic Security Log Dataset},
  year = {2025},
  publisher = {Phantom Armor},
  url = {https://github.com/gregdiy/cyber_simulation}
}
```

---

## Community

**Issues:** Report bugs or request features via GitHub Issues  
**Discussions:** Share detection techniques, ask questions  
**Contributions:** PRs welcome for notebooks, analysis scripts  

---

## Acknowledgments

This work was motivated by real-world challenges encountered while building ML-based detection systems in enterprise security operations. Special thanks to the cybersecurity research community for publicly available threat intelligence and attack documentation that informed the attack modeling.