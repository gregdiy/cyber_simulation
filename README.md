# cyber_simulation

Synthetic cybersecurity log simulator for research, SOC automation testing, and machine learning benchmarking

## About This Project

**Phantom Armor Synthetic Log Simulator** is an open research effort designed to help the security community evaluate detection and SOC automation systems on realistic, labeled, but fully synthetic data.

The dataset is **free for research and benchmarking**. Commercial or production use requires permission.

# Enterprise Security Log Dataset with Embedded MITRE ATT&CK Chain

A fully labeled, synthetic enterprise log dataset with a realistic, multi-stage MITRE ATT&CK chain embedded in normal user, service-account, and infrastructure activity.

---

# WHAT THIS REPO IS

* **Synthetic enterprise environment** spanning 9 days of activity (Nov 16–24, 2025)
* **Realistic security log dataset** with host + network events:

  * Normal user behavior across 500+ employees
  * Background infrastructure & 50+ service accounts
  * One labeled, multi-stage APT attack chain with ground-truth labels
* **ML research platform** for:

  * User and Entity Behavior Analytics (UEBA)
  * Anomaly detection & sequence modeling
  * Attack kill chain reconstruction
  * Role-based behavioral profiling
* **Detection evaluation framework** for:

  * SIEM/EDR rule testing
  * MITRE ATT&CK coverage validation
  * False positive rate benchmarking
* **File-hash and reputation telemetry** for:

  * sha256 / md5 hashes on selected events
  * Realistic file_size, signed flag, prevalence_score per file
* **Educational resource** for:

  * SOC analyst training
  * Cybersecurity curriculum
  * Threat research

# WHAT THIS REPO IS NOT

* Not real customer or production data (fully synthetic)
* Not an open-source log generator (curated dataset only)
* Not affiliated with any employer or vendor
* Not a full benchmark suite (sample scenario)

---

# REPOSITORY CONTENTS

```
├── data/
│   └── enterprise_logs_sample.csv          Full dataset (2,901,947 events)
├── notebooks/
│   ├── 1explore_dataset.ipynb              Schema, distributions, user profiles
├── docs/
│   ├── schema.md                           Complete field documentation
└── README.md                               This file
```

---

# Download & Prepare the Dataset

The full dataset is hosted in Google Cloud Storage as a ZIP file.

### Option 1 – Using gcloud (recommended)

From the root of this repo:

```bash
cd /path/to/cyber_simulation

mkdir -p data

# Download ZIP from GCS
gcloud storage cp \
  gs://phantom-armor-datasets/cyber_simulation/v1/enterprise_logs_sample.zip \
  data/enterprise_logs_sample.zip

# Unzip
unzip data/enterprise_logs_sample.zip -d data

# Optional: delete ZIP
rm data/enterprise_logs_sample.zip
```

You should now have:

```
data/enterprise_logs_sample.csv
```

---

### Option 2 – Using curl (no gcloud required)

```bash
cd /path/to/cyber_simulation

mkdir -p data

curl -o data/enterprise_logs_sample.zip \
  https://storage.googleapis.com/phantom-armor-datasets/cyber_simulation/v1/enterprise_logs_sample.zip

unzip data/enterprise_logs_sample.zip -d data

rm data/enterprise_logs_sample.zip
```

Output:

```
data/enterprise_logs_sample.csv
```

The notebook and any code in this repo assume the dataset is located at that path.

---

# SCENARIO OVERVIEW

## Environment

500 users across Engineering, Finance, Security, Sales, HR, Legal, Operations, Support
Locations: NYC_HQ, SF_Office, London, Remote_VPN

### Infrastructure

* Workstations (~500), mobile devices (~400)
* Servers: Database (6), Web (8), Application (6), Domain Controllers (3)
* Security: SIEM (2), Monitoring (2), Email Security (2), Firewalls (3)
* Infrastructure: File servers, SharePoint, Backup, Print servers

### Service Accounts

50+ service accounts (svc_backup, svc_monitoring, svc_adconnect, etc.)

---

## Dataset Coverage

* Timespan: 9 days (Nov 16–24, 2025)
* Total events: ~2.9M
* Attack ratio: <1%
* Composition: normal workflows + infrastructure noise + multi-day APT intrusion

---

## Embedded Attack

* Attack ID: ATK_63070
* Victim: **linda.davis381** (Security Analyst)
* Duration: 5 days
* Kill chain stages: 16
* MITRE techniques:

  * t1059.001 – PowerShell
  * t1087.002 – Domain Discovery
  * t1021.001 – RDP Lateral Movement
  * t1041 – Exfiltration
* Privilege escalation: user → svc_adconnect
* Targets: DC-01, DC-02
* C2: 203.0.113.70 (ports 8080, 443, 9090)

---

# SCHEMA OVERVIEW

## Core Identifiers

timestamp, user, account, service_account, hostname, device_type, location, network_membership

## User Context

department, role, task_category

## Process & Activity

process_name, parent_process, command_line, event_type

## Network Fields

source_ip, destination_ip, port, protocol

## Attack Labels

attack_id, attack_type, stage_number

## Session Fields

session_id

## File Hash & Reputation Fields

Present **only on events where hashing is triggered** (process/file/network):

* **sha256** – 64-char SHA-256
* **md5** – 32-char MD5
* **file_size** – realistic estimated size
* **signed** – `"true"` or `"false"`
* **prevalence_score** – how common the hash is (0.0–1.0)

---

# EMBEDDED ATTACK: ATK_63070 KILL CHAIN

## Attack Profile

Security Analyst compromised
Living-off-the-land
Service account abuse
Slow, multi-day discovery + lateral movement + exfiltration

### Stages 0–3: Initial Access (t1059.001)

PowerShell bypass, hidden window, reconnaissance, privilege escalation.

### Stages 4–6: Discovery (t1087.002)

AD enumeration, privilege mapping.

### Stages 7–10: Lateral Movement (t1021.001)

RDP to domain controllers, remote PowerShell.

### Stages 11–15: Exfiltration (t1041)

PowerShell, certutil, curl over ports 8080 / 443 / 9090.

---

# Why This Attack Is Hard to Detect

1. Legitimate admin tools overlap heavily with attacker tooling
2. Security analysts routinely use PowerShell/net/mstsc
3. Service accounts look normal even when abused
4. Multi-day dwell time avoids spikes
5. Domain controller access appears legitimate

---

# EXAMPLE ML TASKS

**Event-level detection**, **session compromise detection**, **user compromise**,
**MITRE classification**, **stage prediction**, **sequence modeling**, etc.

---

# KEY DETECTION INSIGHTS

* Role-based modeling is required
* Temporal + sequential context required
* Service account misuse must be detected manually
* Multi-port C2 exfiltration resembles normal traffic

---

# NEXT STEPS

ML engineers, threat researchers, SOC analysts, academics, SOC automation teams,
SIEM/EDR vendors — each has tailored guidance here (kept exactly as in your version).

---

# DATASET STATISTICS

* 2,901,947 total events
* 93 attack events
* <1% attack ratio
* 500+ users
* 50+ service accounts
* 1024 devices
* 4 locations
* 9 days
* 16 kill chain stages
* 4 MITRE techniques

---

# Attribution

**Project:** Phantom Armor (synthetic cybersecurity log simulator)
**Author:** Greg Rothman
**Contact:** **[gregralr@phantomarmor.com](mailto:gregralr@phantomarmor.com)**
**Note:** All data and scenarios are fully synthetic. No real users, systems, or organizations are represented.
