# Enterprise Attack Simulator

**AI-Powered Synthetic Security Log Dataset for Detection Engineering**

---

## What This Is

A **realistic enterprise security log dataset** featuring:
- **8+ million enterprise logs** with realistic background noise
- **Full APT attack campaign** spanning 23 days
- **55+ service accounts** with authentic activity patterns
- **500 users** across 10 departments with role-based behavior
- **Defense product logs** (EDR, DLP, SIEM, PAM, MFA) that react to attacks
- **Labeled ground truth** for every attack action

Built by an ML engineer working in cybersecurity who encountered a common challenge: limited access to realistic, labeled security data for training and testing detection systems.

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

It's one approach to the training data problem, there are certainly others, and this is offered as a research resource for the community.

---

## Sample Dataset Characteristics

### Living Off The Land Attack (Intermediate Skill)

**Attack Profile:**
- **Attacker:** joseph.wilson475 (Security Analyst - blends with normal activity)
- **Campaign:** 23 days (Dec 16 - Jan 7, 2026)
- **Techniques:** PowerShell → Domain Discovery → RDP → Exfiltration
- **Service accounts hijacked:** svc_database, svc_backup, svc_adconnect, svc_fileserver

**Dataset Stats:**
- **Total logs:** 8,108,152
- **Attack logs:** 570 (0.007% - realistic signal-to-noise)
- **Defense alerts:** 209 (37% detection rate)
- **Users:** 500 across 10 departments
- **Service accounts:** 55 generating background activity
- **Timeline:** 25 days of continuous enterprise activity

**Attack Buried in Noise:**
```
joseph.wilson475 (compromised user):
├─ Benign logs: 2,718 (88%)
└─ Attack logs: 361 (12%)

svc_database (hijacked service account):
├─ Benign logs: 185,254 (99.97%)
└─ Attack logs: 64 (0.03%)
```

**Defense Response:**
```
Defender ATP alerts: 71
DLP blocks: 52
SIEM correlation: 14
Credential monitoring: 11
PAM denials: 6
MFA failures: 4
Lateral movement alerts: 3
```

---

## What Makes This Dataset Different

### 1. **Realistic Attack Timelines**
Not compressed lab scenarios - actual APT behavior:
- **Script kiddie:** 7 days (rapid, noisy)
- **Intermediate:** 21-35 days (patient, learning)
- **Advanced:** 60+ days (months-long dwell time)

This dataset: **23 days** (intermediate skill level)

### 2. **Service Account Realism**
55+ service accounts generating millions of background logs:
```
svc_edr_agent: 951K logs (endpoint monitoring)
svc_siem_collector: 935K logs (log collection)
svc_database: 185K logs (includes 64 attack logs - 0.034% signal)
svc_backup: 27K logs (includes 61 attack logs - 0.22% signal)
```

Attack logs are **buried in realistic enterprise noise** - just like real breaches.

### 3. **Defense Product Logs**
Unlike static datasets, this includes logs from defense products:
- **EDR vendors:** CrowdStrike, SentinelOne, Microsoft Defender, Carbon Black
- **Access control:** PAM denials, MFA challenges, NAC quarantine
- **Monitoring:** SIEM alerts, behavioral detection, credential monitoring
- **Network:** Proxy blocks, DLP alerts, lateral movement detection

**Detection rate:** 37% (realistic for intermediate-skill attacker)

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
- Realistic signal-to-noise ratio (0.007% attack signal)
- Service account and user behavior baselines
- Defense product logs as additional features

### **Validating Detection Logic**
- Test whether your rules detect this intermediate-skill attack
- Identify which stages evade detection (37% detection rate in this data)
- Understand false positive rates in realistic noise

### **SOC Analyst Training**
- Practice investigating multi-week campaigns
- Learn to distinguish legitimate from malicious lateral movement
- Navigate enterprise-scale log volumes

### **Research & Education**
- Study APT behavior patterns over realistic timelines
- Analyze service account hijacking techniques
- Understand defense product effectiveness

**Note:** This is a **static dataset** generated from a simulation framework. The full simulation capability (custom defense configurations, different attack chains, varying skill levels) is part of ongoing research work. This dataset represents one specific scenario: a 23-day intermediate-skill living-off-the-land attack.

---

## Repository Contents

```
├── data/
│   └── two_day_sample.csv.gz       # 26MB compressed sample (2 days, included in repo)
├── notebooks/
│   └── explore_dataset.ipynb       # Dataset overview, distributions   
├── docs/
│   └── SCHEMA.md                   # Complete field documentation
│   
└── README.md
```

---

## Quick Start

### Download Dataset

```bash
cd /path/to/cyber_simulation

mkdir -p data

#297 mb compressed
curl -o data/simulation.csv.gz \
   https://huggingface.co/datasets/gregalr/cyber_simulation/resolve/main/simulation.csv.gz

# Load in Python
import pandas as pd
df = pd.read_csv('data/simulation.csv.gz')  # Pandas handles gzip

```

### Explore Tiny Sample (No Download)

```python
import pandas as pd

# Load included sample (25MB, 2 days)
df = pd.read_csv('data/two_day_sample.csv.gz')

# Filter to attack logs
attack = df[df['attack_id'].notna()]
print(f"Attack logs: {len(attack)}")
print(f"Techniques: {attack['attack_type'].unique()}")

# See defense response
defense_logs = df[~df['log_type'].str.startswith('windows', na=False)]
print(f"Defense alerts: {len(defense_logs)}")
```

---

## Schema Overview

### Core Fields
```
timestamp          - ISO 8601: "2025-12-16 01:32:03"
log_type           - "windows_security_event", "defender_atp_alert", etc.
user               - Human identity: "joseph.wilson475"
account            - Security principal (user or svc_*)
hostname           - Device: "WS-SEC-0476", "DB-SRV-01"
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
attack_id          - "ATK_84073" or null
attack_type        - "t1059.001" (MITRE technique) or null
stage_number       - "0" through "15" or null
```

### Defense Logs (30+ types)
```
log_type           - "defender_atp_alert", "dlp_block", "siem_alert"
severity           - low, medium, high, critical
action_taken       - blocked, logged, quarantined, denied
vendor             - CrowdStrike, Microsoft Defender, etc
detection_confidence - 0.0-1.0
alert_name         - "Suspicious PowerShell Activity"
reason             - "Malicious script pattern detected"
```

See `docs/SCHEMA.md` for complete documentation including all defense fields.

---

## Attack Chain: living_off_land_basic

**Threat Actors:** APT29, Cozy Bear, The Dukes  
**Description:** PowerShell-based attack using legitimate tools  
**Flow:** PowerShell execution → Domain discovery → RDP lateral movement → Data exfiltration

### Stage Breakdown

**Stages 0-3: PowerShell Execution (t1059.001)**
```
Dec 16: Initial access attempts (multiple failures)
- powershell.exe -ExecutionPolicy Bypass
- Blocked by: AMSI, AppLocker, Defender
- Attacker learns environment defenses
```

**Stages 4-6: Domain Discovery (t1087.002)**
```
Dec 17-19: Reconnaissance
- net user, whoami, systeminfo
- Get-ADUser, Get-ADGroupMember
- Identifies service accounts and admin groups
```

**Stages 7-10: Lateral Movement (t1021.001)**
```
Dec 23-31: RDP to servers
- mstsc.exe to DB-SRV-01
- Hijacks svc_database account
- Moves to svc_backup, svc_adconnect
```

**Stages 11-15: Exfiltration (t1041)**
```
Jan 2-7: Data theft
- Compress-Archive sensitive files
- Exfil via svc_database permissions
- Multi-stage data transfer
```

---

## Why This Attack Is Hard to Detect

1. **Security analyst tools overlap with attacker tools**  
   PowerShell, net.exe, RDP - all used legitimately by Security dept

2. **Service account activity provides perfect cover**  
   svc_database generates 185K logs - 64 attack logs blend in (0.03%)

3. **Multi-week dwell time avoids spike detection**  
   23-day campaign - no sudden anomaly, gradual progression

4. **Legitimate credentials bypass many controls**  
   Hijacked service accounts have authorized access

5. **Living-off-land techniques**  
   No malware, only built-in Windows tools

---

## Dataset Statistics

```
Total logs:        8,108,152
Attack logs:       570 (0.007%)
Defense alerts:    209 (37% detection rate)
Users:             500
Service accounts:  55
Devices:           1,024
Locations:         4 (NYC, SF, London, Remote VPN)
Duration:          25 days
Attack stages:     16
MITRE techniques:  4
```

---

## How This Dataset Differs

This dataset takes a specific approach to the training data problem. Here's how it compares to other available resources:

### vs. Static Attack Datasets (DARPA 2000, CICIDS, etc.)
- **Similar:** Labeled ground truth, repeatable scenarios
- **Additionally offers:** Multi-week timelines, service account noise, defense product logs
- **Tradeoff:** Single attack scenario vs. diverse attack types in some static datasets

### vs. Pentest/Red Team Platforms (AttackIQ, SafeBreach, Cymulate)
- **Different focus:** Those validate live defenses; this provides training data
- **Complementary:** Use those to test, use this to train
- **Tradeoff:** Not testing real defenses, purely synthetic

### vs. Lab Environments (Cyber ranges, virtual labs)
- **Similar:** Controlled, repeatable scenarios
- **Additionally offers:** Enterprise-scale noise (8M logs), realistic service account activity
- **Tradeoff:** Can't interact with attack in real-time like in a live lab

### vs. Real Breach Data
- **Cannot replace:** Nothing beats analyzing real incidents
- **Useful when:** Real data is unavailable, sensitive, or can't be shared
- **Tradeoff:** Synthetic means it won't capture all real-world edge cases

**This dataset is not a replacement for any of these—it's another tool in the toolkit.** It's particularly useful when you need labeled, repeatable, shareable data at enterprise scale.

For a detailed feature comparison, see [`docs/COMPARISON.md`](docs/COMPARISON.md).

---

## Known Limitations

This dataset represents one specific scenario and has several limitations:

- **Single attack chain:** Only "living_off_the-land_basic" (PowerShell → discovery → RDP → exfil)
- **One skill level:** Intermediate attacker (40-50% failure rate)
- **One defense configuration:** Represents a common enterprise stack but not customizable in this static dataset
- **Synthetic data:** Fully simulated—doesn't capture all real-world complexity
- **Static snapshot:** Can't adjust attack parameters or generate new scenarios from this dataset alone
- **No cloud attacks:** Pure on-premises environment (AWS/Azure not included in this release)

The simulation framework that generated this dataset supports multiple attack chains, skill levels, and defense configurations, but those capabilities are part of ongoing research work. This release focuses on providing one high-quality, realistic scenario.

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
- FireEye: Advanced attackers → 60-90 days
- This dataset: 23 days for intermediate = realistic

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

## Roadmap

**Current Release (v1.0):**
- 1 attack chain (living_off_land_basic)
- Intermediate skill level
- 55 service accounts
- Multiple defense products

**Planned Future Work:**
- Additional attack chains (credential harvesting, ransomware, etc.)
- Multiple skill levels (script kiddie → nation-state)
- Cloud attack scenarios (AWS/Azure)
- Customizable defense configurations

The full simulation framework that enables these capabilities is part of ongoing research. Feedback and collaboration welcome.

---

## Acknowledgments

This work was motivated by real-world challenges encountered while building ML-based detection systems in enterprise security operations. Special thanks to the cybersecurity research community for publicly available threat intelligence and attack documentation that informed the attack modeling.