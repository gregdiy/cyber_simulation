# Synthetic Security Log Dataset

A personal research project exploring how security detections perform in realistic, multi-step attack scenarios.

---

## What This Reveals

Security detections are often evaluated on isolated signals.

In realistic environments, attacks unfold as multi-step sequences over time.

This dataset explores a simple question:

> Do detections capture the progression of an attack, or mostly isolated, noisy events?

---

## What This Is

A synthetic security log dataset representing a multi-week enterprise environment with:

- Normal user activity across departments
- Service account behavior and background system activity
- A multi-step attack sequence embedded within normal operations
- Row-level labels for attack-related activity (`attack_id`)

The goal is to provide a controlled environment for:

- Exploring detection coverage
- Understanding how attacks blend into normal behavior
- Testing simple detection logic against realistic noise

---

## Key Characteristics

- ~7.9 million log events over 25 days
- Multi-user environment with role-based behavior
- Service accounts with high-volume background activity
- Multi-stage attack sequence spanning multiple identities and hosts
- Ground truth labels for attacker actions (`attack_id`)

---

## Example Pattern

A simplified example of activity that appears normal in isolation:

1. User logs in
2. Runs PowerShell
3. Connects to a new server
4. Uses a service account

Each event may be expected in an enterprise environment.

In sequence, it can represent attack behavior.

---

## Repository Contents

```
.
├── data/
│   └── two_day_sample_cyber_simulator_json_format.zip
├── notebooks/
│   └── explore_dataset.ipynb
├── docs/
│   └── SCHEMA.md
├── evaluate.py
└── README.md
```

---

## Quick Start

### Load sample data

```python
import json
import zipfile

records = []

with zipfile.ZipFile("data/two_day_sample_cyber_simulator_json_format.zip") as zf:
    for name in zf.namelist():
        if name.endswith(".json"):
            with zf.open(name) as f:
                for line in f:
                    line = line.decode("utf-8").strip()
                    if line:
                        records.append(json.loads(line))

print("Loaded records:", len(records))

attack = [r for r in records if r.get("attack_id") is not None]
print("Attack records:", len(attack))
```

---

## Evaluating Detection Logic

The repository includes a simple evaluator for testing detection approaches.

Example workflow:

- Filter for specific behaviors (e.g., PowerShell usage)
- Compare detected rows to labeled attack activity
- Measure precision / recall

---

## Why This Matters

In real environments:

- Attacks often use legitimate tools
- Behavior overlaps with normal administrative activity
- High log volume makes weak signals difficult to interpret

This dataset is intended to explore how these factors affect detection.

---

## Scope

This is a synthetic dataset representing a single scenario.

It is intended for:

- Experimentation
- Learning
- Exploration of detection behavior

---

## Notes

- All data is synthetic
- No real users, systems, or organizations are represented
- This is a personal research project developed independently