from __future__ import annotations

import argparse
import csv
import json
import math
import sys
from collections import Counter, defaultdict
from dataclasses import dataclass
from datetime import date, timedelta
from typing import Dict, Iterable, List, Optional

import numpy as np
import pandas as pd


NA_STRINGS = {"", "NA", "N/A", "null", "None", "nan", "NaN"}


def _norm_str(x) -> str:
    if x is None:
        return ""
    if isinstance(x, float) and math.isnan(x):
        return ""
    return str(x).strip()


def _is_present(x) -> bool:
    s = _norm_str(x)
    return s != "" and s not in NA_STRINGS


def _date_range_inclusive(start_yyyy_mm_dd: str, end_yyyy_mm_dd: str) -> List[str]:
    if not start_yyyy_mm_dd or not end_yyyy_mm_dd:
        return []
    try:
        y1, m1, d1 = map(int, start_yyyy_mm_dd.split("-"))
        y2, m2, d2 = map(int, end_yyyy_mm_dd.split("-"))
        cur = date(y1, m1, d1)
        end = date(y2, m2, d2)
        out = []
        while cur <= end:
            out.append(cur.isoformat())
            cur += timedelta(days=1)
        return out
    except Exception:
        return []


@dataclass
class SparseRowIdMatcher:
    row_ids: np.ndarray

    @classmethod
    def from_iterable(cls, ids: Iterable[int]) -> "SparseRowIdMatcher":
        arr = np.fromiter(ids, dtype=np.int64)
        if arr.size == 0:
            return cls(arr)
        arr = np.unique(arr)
        arr.sort()
        return cls(arr)

    def mask_for_range(self, start: int, length: int) -> np.ndarray:
        if self.row_ids.size == 0:
            return np.zeros(length, dtype=bool)
        end = start + length
        left = np.searchsorted(self.row_ids, start, side="left")
        right = np.searchsorted(self.row_ids, end, side="left")
        if right <= left:
            return np.zeros(length, dtype=bool)
        rel = self.row_ids[left:right] - start
        mask = np.zeros(length, dtype=bool)
        mask[rel] = True
        return mask


def load_prediction_row_ids(pred_path: str, col: str = "row_id") -> SparseRowIdMatcher:
    if pred_path is None:
        return SparseRowIdMatcher.from_iterable([])

    try:
        with open(pred_path, "r", encoding="utf-8") as f:
            obj = json.load(f)
        if isinstance(obj, list):
            return SparseRowIdMatcher.from_iterable(int(x) for x in obj)
        if isinstance(obj, dict) and "row_ids" in obj and isinstance(obj["row_ids"], list):
            return SparseRowIdMatcher.from_iterable(int(x) for x in obj["row_ids"])
    except Exception:
        pass

    try:
        with open(pred_path, "r", encoding="utf-8", errors="ignore") as f:
            sample = f.read(4096)
        dialect = csv.Sniffer().sniff(sample, delimiters=",\t;|")
        df = pd.read_csv(pred_path, sep=dialect.delimiter)
        if col in df.columns:
            ids = df[col].dropna().astype(np.int64).tolist()
            return SparseRowIdMatcher.from_iterable(ids)
    except Exception:
        pass

    ids: List[int] = []
    with open(pred_path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            s = line.strip()
            if not s or s.startswith("#"):
                continue
            try:
                ids.append(int(s))
            except ValueError:
                continue
    return SparseRowIdMatcher.from_iterable(ids)


def compute_metrics(tp: int, fp: int, fn: int) -> Dict[str, float]:
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) else 0.0
    return {"precision": precision, "recall": recall, "f1": f1}


def daily_stats(
    fp_by_date: Dict[str, int],
    alerts_by_date: Dict[str, int],
    start_date: str,
    end_date: str,
) -> Dict[str, float]:
    days = _date_range_inclusive(start_date, end_date)
    if not days:
        return {"days": 0, "fp_per_day_avg": 0.0, "alerts_per_day_avg": 0.0, "fp_per_day_p95": 0.0, "alerts_per_day_p95": 0.0}
    fp = np.array([fp_by_date.get(d, 0) for d in days], dtype=float)
    al = np.array([alerts_by_date.get(d, 0) for d in days], dtype=float)
    return {
        "days": int(len(days)),
        "fp_per_day_avg": float(fp.mean()),
        "alerts_per_day_avg": float(al.mean()),
        "fp_per_day_p95": float(np.percentile(fp, 95)),
        "alerts_per_day_p95": float(np.percentile(al, 95)),
    }


def evaluate(
    data_path: str,
    pred_matcher: SparseRowIdMatcher,
    *,
    sep: str = "\t",
    chunksize: int = 1_000_000,
    baseline_defense: bool = True,
    timestamp_col: str = "timestamp",
    attack_id_col: str = "attack_id",
    attack_type_col: str = "attack_type",
    stage_col: str = "stage_number",
    defense_alert_col: str = "alert_name",
    label_col_fallback: str = "label",
) -> Dict[str, object]:

    header = pd.read_csv(data_path, sep=sep, compression="infer", nrows=0)
    cols = set(header.columns)

    log_type_col = "log_type"
    needed = [timestamp_col, attack_id_col, attack_type_col, stage_col, defense_alert_col, label_col_fallback, log_type_col]
    usecols = [c for c in needed if c in cols]

    if attack_id_col not in cols and label_col_fallback not in cols:
        raise ValueError(f"Dataset must contain '{attack_id_col}' or '{label_col_fallback}' for ground truth.")

    sub_tp = 0
    sub_fp = 0
    total_attack = 0

    base_tp = 0
    base_fp = 0
    base_alerts_total = 0

    sub_fp_by_date: Dict[str, int] = defaultdict(int)
    sub_alerts_by_date: Dict[str, int] = defaultdict(int)

    base_fp_by_date: Dict[str, int] = defaultdict(int)
    base_alerts_by_date: Dict[str, int] = defaultdict(int)

    attack_by_tech = Counter()
    detected_by_tech = Counter()

    attack_by_stage = Counter()
    detected_by_stage = Counter()

    first_attack_ts: Dict[str, str] = {}
    first_detect_ts: Dict[str, str] = {}

    min_date = None
    max_date = None

    reader = pd.read_csv(
        data_path,
        sep=sep,
        compression="infer",
        usecols=usecols,
        chunksize=chunksize,
        low_memory=True,
    )

    row_offset = 0
    for chunk in reader:
        n = len(chunk)

        if timestamp_col in chunk.columns:
            ts_series = chunk[timestamp_col].astype(str)
            dates = ts_series.str.slice(0, 10)
            dmin = dates.min()
            dmax = dates.max()
            if min_date is None or dmin < min_date:
                min_date = dmin
            if max_date is None or dmax > max_date:
                max_date = dmax
            dates_np = dates.to_numpy(dtype=str)
        else:
            dates_np = np.array([""] * n, dtype=str)

 
        if attack_id_col in chunk.columns:
            atk = chunk[attack_id_col]
            atk_str = atk.astype(str).str.strip()
            is_attack_related = atk.notna() & (~atk_str.isin(list(NA_STRINGS))) & (atk_str != "")
        else:
            lbl = chunk[label_col_fallback].astype(str).str.strip()
            is_attack_related = lbl.isin({"1", "true", "True", "attack", "ATTACK"})

        if "log_type" not in chunk.columns:
            raise ValueError("Benchmark requires 'log_type' column to score windows_security_event only.")

        is_scored = chunk["log_type"].astype(str).str.strip().eq("windows_security_event")
        is_attack = is_attack_related & is_scored

        is_scored_np = is_scored.to_numpy(dtype=bool)
        is_attack_np = is_attack.to_numpy(dtype=bool)

        attack_count_chunk = int(is_attack_np.sum())
        total_attack += attack_count_chunk


        pred_mask_np = pred_matcher.mask_for_range(row_offset, n)

        tp_chunk = int(np.logical_and(pred_mask_np, is_attack_np).sum())
        fp_chunk = int(np.logical_and(pred_mask_np, ~is_attack_np).sum())
        sub_tp += tp_chunk
        sub_fp += fp_chunk

        if pred_mask_np.any():
            for d in dates_np[pred_mask_np]:
                if d:
                    sub_alerts_by_date[d] += 1
        if fp_chunk:
            for d in dates_np[np.logical_and(pred_mask_np, ~is_attack_np)]:
                if d:
                    sub_fp_by_date[d] += 1

        if attack_count_chunk:
            attack_idx = np.where(is_attack_np)[0]

            if attack_type_col in chunk.columns:
                tech_vals = chunk.iloc[attack_idx][attack_type_col].astype(str).str.strip().to_numpy()
                for t in tech_vals:
                    if _is_present(t):
                        attack_by_tech[t] += 1

            if stage_col in chunk.columns:
                stage_vals = chunk.iloc[attack_idx][stage_col].astype(str).str.strip().to_numpy()
                for s in stage_vals:
                    if _is_present(s):
                        attack_by_stage[s] += 1

            if attack_id_col in chunk.columns and timestamp_col in chunk.columns:
                atk_ids = chunk.iloc[attack_idx][attack_id_col].astype(str).str.strip().to_numpy()
                ts_vals = chunk.iloc[attack_idx][timestamp_col].astype(str).str.strip().to_numpy()
                for aid, tsv in zip(atk_ids, ts_vals):
                    if not _is_present(aid) or not _is_present(tsv):
                        continue
                    prev = first_attack_ts.get(aid)
                    if prev is None or tsv < prev:
                        first_attack_ts[aid] = tsv

        pred_attack_idx = np.where(np.logical_and(pred_mask_np, is_attack_np))[0]
        if pred_attack_idx.size:
            if attack_type_col in chunk.columns:
                tech_vals = chunk.iloc[pred_attack_idx][attack_type_col].astype(str).str.strip().to_numpy()
                for t in tech_vals:
                    if _is_present(t):
                        detected_by_tech[t] += 1
            if stage_col in chunk.columns:
                stage_vals = chunk.iloc[pred_attack_idx][stage_col].astype(str).str.strip().to_numpy()
                for s in stage_vals:
                    if _is_present(s):
                        detected_by_stage[s] += 1
            if attack_id_col in chunk.columns and timestamp_col in chunk.columns:
                atk_ids = chunk.iloc[pred_attack_idx][attack_id_col].astype(str).str.strip().to_numpy()
                ts_vals = chunk.iloc[pred_attack_idx][timestamp_col].astype(str).str.strip().to_numpy()
                for aid, tsv in zip(atk_ids, ts_vals):
                    if not _is_present(aid) or not _is_present(tsv):
                        continue
                    prev = first_detect_ts.get(aid)
                    if prev is None or tsv < prev:
                        first_detect_ts[aid] = tsv


        row_offset += n

    sub_fn = total_attack - sub_tp
    sub_metrics = compute_metrics(sub_tp, sub_fp, sub_fn)

    results: Dict[str, object] = {
        "dataset": {
            "path": data_path,
            "rows": int(row_offset),
            "attack_events": int(total_attack),
            "date_range": {"start": min_date, "end": max_date},
        },
        "submission": {
            "predicted_alert_rows": int(pred_matcher.row_ids.size),
            "tp": int(sub_tp),
            "fp": int(sub_fp),
            "fn": int(sub_fn),
            **sub_metrics,
            "daily_stats": daily_stats(sub_fp_by_date, sub_alerts_by_date, min_date or "", max_date or ""),
        },
        "breakdown": {
            "recall_by_attack_type": {},
            "recall_by_stage": {},
        },
        "time_to_detect": {
            "per_attack_id": {},
        },
    }

    if pred_matcher.row_ids.size:
        oob = int((pred_matcher.row_ids < 0).sum() + (pred_matcher.row_ids >= row_offset).sum())
        results["submission"]["predicted_row_ids_out_of_bounds"] = oob

    recall_by_tech = {}
    for tech, total in attack_by_tech.items():
        det = detected_by_tech.get(tech, 0)
        recall_by_tech[tech] = {"detected": int(det), "total": int(total), "recall": (det / total) if total else 0.0}

    recall_by_stage = {}
    for st, total in attack_by_stage.items():
        det = detected_by_stage.get(st, 0)
        recall_by_stage[st] = {"detected": int(det), "total": int(total), "recall": (det / total) if total else 0.0}

    results["breakdown"]["recall_by_attack_type"] = dict(sorted(recall_by_tech.items(), key=lambda kv: kv[0]))

    def _stage_key(k: str):
        try:
            return int(k)
        except Exception:
            return 10**9

    results["breakdown"]["recall_by_stage"] = dict(sorted(recall_by_stage.items(), key=lambda kv: _stage_key(kv[0])))

    ttd = {}
    for aid, t0 in first_attack_ts.items():
        t1 = first_detect_ts.get(aid)
        entry = {"first_attack_ts": t0, "first_detect_ts": t1, "detected": t1 is not None}
        if t1 is not None:
            try:
                dt0 = pd.to_datetime(t0)
                dt1 = pd.to_datetime(t1)
                entry["time_to_detect_seconds"] = float((dt1 - dt0).total_seconds())
                entry["time_to_detect_hours"] = float((dt1 - dt0).total_seconds() / 3600.0)
            except Exception:
                pass
        ttd[aid] = entry
    results["time_to_detect"]["per_attack_id"] = dict(sorted(ttd.items(), key=lambda kv: kv[0]))

    if baseline_defense and defense_alert_col in cols:
        base_fn = total_attack - base_tp
        base_metrics = compute_metrics(base_tp, base_fp, base_fn)
        results["baseline_defense_alert_name"] = {
            "tp": int(base_tp),
            "fp": int(base_fp),
            "fn": int(base_fn),
            "alerts_total": int(base_alerts_total),
            **base_metrics,
            "daily_stats": daily_stats(base_fp_by_date, base_alerts_by_date, min_date or "", max_date or ""),
        }

    return results


def main() -> None:
    ap = argparse.ArgumentParser(description="Evaluate sparse alerts against the cyber_simulation dataset.")
    ap.add_argument("--data", required=True, help="Path to dataset file (e.g., data/simulation.csv.gz).")
    ap.add_argument("--pred", default=None, help="Path to predictions file (row_id list).")
    ap.add_argument("--pred-col", default="row_id", help='Column name to read row ids from (if CSV/TSV). Default: "row_id"')
    ap.add_argument("--sep", default="\t", help="Dataset delimiter. Default: tab")
    ap.add_argument("--chunksize", type=int, default=1_000_000, help="Rows per chunk. Default: 1,000,000")
    ap.add_argument("--no-baseline", action="store_true", help="Disable defense baseline (alert_name).")
    ap.add_argument("--out", default=None, help="Write metrics JSON to this file.")
    args = ap.parse_args()

    pred_matcher = load_prediction_row_ids(args.pred, col=args.pred_col) if args.pred else SparseRowIdMatcher.from_iterable([])
    results = evaluate(
        data_path=args.data,
        pred_matcher=pred_matcher,
        sep=args.sep,
        chunksize=args.chunksize,
        baseline_defense=not args.no_baseline,
    )

    out_json = json.dumps(results, indent=2)
    print(out_json)

    if args.out:
        with open(args.out, "w", encoding="utf-8") as f:
            f.write(out_json)
        print(f"\nWrote: {args.out}", file=sys.stderr)


if __name__ == "__main__":
    main()
