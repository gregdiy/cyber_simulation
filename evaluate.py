#!/usr/bin/env python3
import argparse
import csv
import json
import zipfile
from datetime import datetime, timezone
from typing import Any, Dict, Set, Optional
import os
from typing import Set


try:
    import orjson  # pip install orjson
    def loads(b: bytes) -> Dict[str, Any]:
        return orjson.loads(b)
except Exception:
    def loads(b: bytes) -> Dict[str, Any]:
        return json.loads(b.decode("utf-8"))

def read_pred_row_ids(path: str) -> Set[int]:
    p = path.lower()
    _, ext = os.path.splitext(p)

    # JSON list: [1,2,3]
    if ext == ".json":
        with open(path, "r", encoding="utf-8") as f:
            obj = json.load(f)
        if not isinstance(obj, list):
            raise ValueError("Prediction JSON must be a list of integers.")
        return {int(x) for x in obj}

    # CSV/TSV with row_id column
    if ext in (".csv", ".tsv"):
        # Try comma, then tab — no Sniffer.
        for delim in (",", "\t"):
            with open(path, "r", encoding="utf-8", newline="") as f:
                r = csv.DictReader(f, delimiter=delim)
                if not r.fieldnames:
                    continue
                if "row_id" not in r.fieldnames:
                    continue
                out = set()
                for row in r:
                    v = row.get("row_id")
                    if v is not None and str(v).strip() != "":
                        out.add(int(v))
                if out or True:
                    return out

        raise ValueError(f"{path} must contain a 'row_id' column (comma or tab separated).")

    # Plain text: one int per line
    out = set()
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            s = line.strip()
            if s:
                out.add(int(s))
    return out

    # plain text
    out = set()
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            s = line.strip()
            if s:
                out.add(int(s))
    return out

def is_attack_id(x: Any) -> bool:
    if x is None:
        return False
    s = str(x).strip()
    if s == "" or s.upper() == "NA" or s.lower() == "null":
        return False
    return True

def parse_iso(ts: str) -> datetime:
    # Handles "2025-12-29T23:12:04.000-08:00"
    # datetime.fromisoformat is fast and works here
    dt = datetime.fromisoformat(ts)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", required=True, help="Path to cyber_simulator_json_format.zip")
    ap.add_argument("--pred", required=True, help="Predictions file (csv/tsv/json/txt) containing row_id(s)")
    ap.add_argument("--out", required=True, help="Output metrics.json")
    ap.add_argument("--zip-order", action="store_true",
                    help="Use zf.namelist() order. Default is sorted(zf.namelist()) for deterministic row_id.")
    args = ap.parse_args()

    pred = read_pred_row_ids(args.pred)

    eligible_rows = 0
    positives = 0

    tp = 0
    fp = 0

    # For FN we can compute at end: FN = positives - tp
    # For TN we need eligible_rows - tp - fp - fn

    # Stage / technique breakdown (only track for true positives universe)
    true_by_stage: Dict[str, int] = {}
    tp_by_stage: Dict[str, int] = {}
    true_by_tech: Dict[str, int] = {}
    tp_by_tech: Dict[str, int] = {}

    # Timing
    first_eligible_ts: Optional[str] = None
    last_eligible_ts: Optional[str] = None
    first_attack_ts: Optional[str] = None
    first_tp_ts: Optional[str] = None

    row_id = 0

    with zipfile.ZipFile(args.data) as zf:
        members = zf.namelist()
        if not args.zip_order:
            members = sorted(members)

        for name in members:
            if not name.endswith(".json"):
                continue
            with zf.open(name) as f:
                for line in f:
                    if not line.strip():
                        row_id += 1
                        continue

                    obj = loads(line)

                    if obj.get("log_type") == "windows_security_event":
                        eligible_rows += 1

                        ts = obj.get("timestamp")
                        if ts:
                            if first_eligible_ts is None:
                                first_eligible_ts = ts
                            last_eligible_ts = ts  # assumes roughly chronological ordering

                        is_pos = is_attack_id(obj.get("attack_id"))
                        if is_pos:
                            positives += 1
                            if first_attack_ts is None and ts:
                                first_attack_ts = ts

                            stage = str(obj.get("stage_number")) if obj.get("stage_number") is not None else "null"
                            tech = str(obj.get("attack_type")) if obj.get("attack_type") is not None else "null"
                            true_by_stage[stage] = true_by_stage.get(stage, 0) + 1
                            true_by_tech[tech] = true_by_tech.get(tech, 0) + 1

                        if row_id in pred:
                            if is_pos:
                                tp += 1
                                if first_tp_ts is None and ts:
                                    first_tp_ts = ts
                                # breakdown TP buckets
                                stage = str(obj.get("stage_number")) if obj.get("stage_number") is not None else "null"
                                tech = str(obj.get("attack_type")) if obj.get("attack_type") is not None else "null"
                                tp_by_stage[stage] = tp_by_stage.get(stage, 0) + 1
                                tp_by_tech[tech] = tp_by_tech.get(tech, 0) + 1
                            else:
                                fp += 1

                    row_id += 1

    fn = positives - tp
    tn = eligible_rows - tp - fp - fn

    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) else 0.0

    # FP/day and TTD — parse only a couple timestamps
    fp_per_day = None
    if first_eligible_ts and last_eligible_ts:
        t0 = parse_iso(first_eligible_ts)
        t1 = parse_iso(last_eligible_ts)
        days = max((t1 - t0).total_seconds() / 86400.0, 1e-9)
        fp_per_day = fp / days

    ttd_seconds = None
    if first_attack_ts and first_tp_ts:
        t_attack = parse_iso(first_attack_ts)
        t_first_tp = parse_iso(first_tp_ts)
        ttd_seconds = (t_first_tp - t_attack).total_seconds()

    recall_by_stage = {
        k: (tp_by_stage.get(k, 0) / v) for k, v in true_by_stage.items() if v > 0
    }
    recall_by_technique = {
        k: (tp_by_tech.get(k, 0) / v) for k, v in true_by_tech.items() if v > 0
    }

    metrics = {
        "eligible_rows": eligible_rows,
        "positives": positives,
        "predictions_total": len(pred),
        "tp": tp, "fp": fp, "fn": fn, "tn": tn,
        "precision": precision, "recall": recall, "f1": f1,
        "fp_per_day": fp_per_day,
        "time_to_detect_seconds": ttd_seconds,
        "time_to_detect_minutes": (ttd_seconds / 60.0) if ttd_seconds is not None else None,
        "recall_by_stage": dict(sorted(recall_by_stage.items(), key=lambda x: x[0])),
        "recall_by_technique": dict(sorted(recall_by_technique.items(), key=lambda x: x[0])),
    }

    with open(args.out, "w", encoding="utf-8") as f:
        json.dump(metrics, f, indent=2)

    print("Wrote", args.out)

if __name__ == "__main__":
    main()
