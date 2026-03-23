#!/usr/bin/env python3
import argparse
import csv
import json
import math
import sqlite3
import statistics
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Mapping, Optional, Tuple
from urllib import parse

import httpx

SQLI_PAYLOADS = [
    "admin' OR '1'='1'--",
    "1 UNION SELECT 1,2,3--",
    "' OR 1=1#",
    "1; DROP TABLE users;--",
]

XSS_PAYLOADS = [
    "<script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "javascript:alert(1)",
    "<svg onload=alert(1)>",
]

MISC_PAYLOADS = [
    "../../etc/passwd",
    "..%2f..%2f..%2fwindows/win.ini",
    "$(whoami)",
    "; cat /etc/passwd;",
]


def iso_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def percentile(values: List[float], p: float) -> float:
    if not values:
        return 0.0
    s = sorted(values)
    idx = int(math.floor(p * (len(s) - 1)))
    return float(s[idx])


def _parse_server_timing_ms(headers: Optional[Mapping[str, str]]) -> Optional[float]:
    """Best-effort parser for common server processing time headers."""
    if not headers:
        return None

    # Common header names across frameworks/proxies.
    candidates = [
        "X-Process-Time",       # often seconds in FastAPI middleware examples
        "X-Response-Time",      # may be "123ms" or raw number
        "Server-Timing",        # e.g. "app;dur=12.3"
        "X-Runtime",            # commonly seconds
    ]

    for key in candidates:
        raw = headers.get(key)
        if not raw:
            continue

        val = str(raw).strip().lower()

        # Server-Timing: find first dur= token.
        if key == "Server-Timing":
            parts = val.split("dur=")
            if len(parts) > 1:
                token = parts[1].split(",")[0].split(";")[0].strip()
                try:
                    return round(float(token), 2)  # dur is already in ms by spec
                except Exception:
                    continue

        try:
            if val.endswith("ms"):
                return round(float(val[:-2].strip()), 2)
            num = float(val)
            # Heuristic: tiny values are likely seconds, large values likely already ms.
            if num <= 10:
                return round(num * 1000.0, 2)
            return round(num, 2)
        except Exception:
            continue

    return None


def request_once(client: httpx.Client, url: str) -> Tuple[int, float, Optional[float], Optional[str]]:
    start = time.perf_counter()
    server_ms: Optional[float] = None
    try:
        resp = client.get(url)
        status = int(resp.status_code)
        server_ms = _parse_server_timing_ms(resp.headers)
        err_kind = None
    except httpx.TimeoutException:
        status = 0
        err_kind = "timeout"
    except httpx.ConnectError:
        status = 0
        err_kind = "connection_refused"
    except httpx.RequestError:
        status = 0
        err_kind = "request_error"
    except Exception:
        status = 0
        err_kind = "exception"
    elapsed_ms = round((time.perf_counter() - start) * 1000.0, 2)
    return status, elapsed_ms, server_ms, err_kind


def run_trial(
    base_url: str,
    timeout: float,
    user_agent: str,
    benign_count: int,
    attack_repeat: int,
    burst_count: int,
    request_pause_ms: float,
    progress_every: int,
    max_status0_ratio: float,
    max_consecutive_status0: int,
    min_requests_before_abort: int,
) -> List[Dict]:
    rows: List[Dict] = []
    pause_s = max(0.0, request_pause_ms / 1000.0)
    total_reqs = benign_count + ((len(SQLI_PAYLOADS) + len(XSS_PAYLOADS) + len(MISC_PAYLOADS)) * attack_repeat) + burst_count
    status0_count = 0
    consecutive_status0 = 0
    client = httpx.Client(timeout=timeout, follow_redirects=False, trust_env=False, headers={"User-Agent": user_agent})

    def hit(label: str, url: str):
        nonlocal status0_count, consecutive_status0
        status, latency_ms, server_ms, err_kind = request_once(client, url)
        rows.append(
            {
                "label": label,
                "status": status,
                "latency_ms": latency_ms,
                "server_processing_ms": server_ms,
                "error_kind": err_kind,
            }
        )

        if status == 0:
            status0_count += 1
            consecutive_status0 += 1
        else:
            consecutive_status0 = 0

        done = len(rows)
        if progress_every > 0 and (done % progress_every == 0 or done == total_reqs):
            elapsed = sum(float(r["latency_ms"]) for r in rows) / 1000.0
            avg = elapsed / max(1, done)
            eta = max(0.0, (total_reqs - done) * avg)
            print(
                f"[trial progress] {done}/{total_reqs} "
                f"status0={status0_count} ({(status0_count / done) * 100.0:.1f}%) "
                f"avg={avg:.3f}s eta={eta:.1f}s"
            )

        if done >= max(1, min_requests_before_abort):
            ratio = status0_count / max(1, done)
            if ratio >= max_status0_ratio:
                raise RuntimeError(
                    f"Fail-fast: status=0 ratio reached {ratio:.2f} "
                    f"after {done} requests (threshold {max_status0_ratio:.2f})."
                )
        if consecutive_status0 >= max_consecutive_status0:
            raise RuntimeError(
                f"Fail-fast: consecutive status=0 reached {consecutive_status0} "
                f"(threshold {max_consecutive_status0})."
            )

        if pause_s > 0:
            time.sleep(pause_s)

    try:
        for _ in range(benign_count):
            hit("benign", f"{base_url}/")

        for p in SQLI_PAYLOADS:
            q = parse.quote(p, safe="")
            for _ in range(attack_repeat):
                hit("sqli", f"{base_url}/protected/admin?username={q}")

        for p in XSS_PAYLOADS:
            q = parse.quote(p, safe="")
            for _ in range(attack_repeat):
                hit("xss", f"{base_url}/protected/search?q={q}")

        for p in MISC_PAYLOADS:
            q = parse.quote(p, safe="")
            for _ in range(attack_repeat):
                hit("misc", f"{base_url}/protected/file?name={q}")

        for _ in range(burst_count):
            hit("burst", f"{base_url}/")
    finally:
        client.close()

    return rows


def summarize(rows: List[Dict]) -> Dict:
    all_rows = [r for r in rows if r["status"] > 0]
    lat = [float(r["latency_ms"]) for r in all_rows]
    p50 = percentile(lat, 0.50)
    p95 = percentile(lat, 0.95)

    total = len(rows)
    blocked = sum(1 for r in rows if r["status"] == 403)
    sum_ms = sum(float(r["latency_ms"]) for r in rows)
    throughput = round(total / (sum_ms / 1000.0), 2) if sum_ms > 0 else 0.0

    attacks = [r for r in rows if r["label"] in {"sqli", "xss", "misc"}]
    benign = [r for r in rows if r["label"] == "benign"]

    tp = sum(1 for r in attacks if r["status"] == 403)
    fn = sum(1 for r in attacks if r["status"] != 403)
    fp = sum(1 for r in benign if r["status"] == 403)
    tn = sum(1 for r in benign if r["status"] != 403)

    precision = round(tp / (tp + fp), 4) if (tp + fp) else 0.0
    recall = round(tp / (tp + fn), 4) if (tp + fn) else 0.0
    f1 = round((2 * precision * recall) / (precision + recall), 4) if (precision + recall) else 0.0
    fpr = round(fp / (fp + tn), 4) if (fp + tn) else 0.0
    status0 = sum(1 for r in rows if r["status"] == 0)
    server_vals = [float(r["server_processing_ms"]) for r in rows if r.get("server_processing_ms") is not None]

    return {
        "total_requests": total,
        "blocked_403": blocked,
        "p50_ms": round(p50, 2),
        "p95_ms": round(p95, 2),
        "throughput_req_per_sec": throughput,
        "tp": tp,
        "fp": fp,
        "fn": fn,
        "tn": tn,
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "false_positive_rate": fpr,
        "status_0_count": status0,
        "status_0_ratio": round(status0 / total, 4) if total else 0.0,
        "latency_basis": "client_end_to_end_ms",
        "server_timing_sample_count": len(server_vals),
        "server_p50_ms": round(percentile(server_vals, 0.50), 2) if server_vals else None,
        "server_p95_ms": round(percentile(server_vals, 0.95), 2) if server_vals else None,
    }


def collect_soc_window_metrics(db_path: Path, t0_iso: str, t1_iso: str) -> Dict:
    if not db_path.exists():
        return {
            "alerts_created": 0,
            "avg_alert_pipeline_delay_ms": None,
            "p95_alert_pipeline_delay_ms": None,
            "avg_sys_cpu": None,
            "p95_sys_cpu": None,
            "avg_sys_memory": None,
            "p95_sys_memory": None,
            "detection_source_counts": {},
        }

    # ThreatLoom stores timestamps in "YYYY-MM-DD HH:MM:SS.sss" format, while
    # runner windows are ISO8601 ("YYYY-MM-DDTHH:MM:SS.sss+00:00"). Normalize
    # window bounds before SQL comparisons to avoid empty-window false negatives.
    try:
        t0_sql = datetime.fromisoformat(t0_iso.replace("Z", "+00:00")).strftime("%Y-%m-%d %H:%M:%S.%f")
        t1_sql = datetime.fromisoformat(t1_iso.replace("Z", "+00:00")).strftime("%Y-%m-%d %H:%M:%S.%f")
    except Exception:
        t0_sql = t0_iso.replace("T", " ").replace("Z", "")
        t1_sql = t1_iso.replace("T", " ").replace("Z", "")

    conn = sqlite3.connect(db_path)
    cur = conn.cursor()

    cur.execute(
        """
        SELECT id, detection_source, created_at, correlated_log_ids
        FROM alerts
        WHERE created_at >= ? AND created_at <= ?
        """,
        (t0_sql, t1_sql),
    )
    alerts = cur.fetchall()

    src_counts: Dict[str, int] = {}
    delays: List[float] = []

    for alert_id, source, created_at, correlated_ids_json in alerts:
        src_counts[source or "unknown"] = src_counts.get(source or "unknown", 0) + 1
        try:
            corr = json.loads(correlated_ids_json or "[]")
        except Exception:
            corr = []

        if not corr:
            continue

        qmarks = ",".join("?" for _ in corr)
        cur.execute(
            f"SELECT MAX(received_at) FROM firewall_logs WHERE id IN ({qmarks})",
            tuple(corr),
        )
        last_recv = cur.fetchone()[0]
        if last_recv and created_at:
            try:
                t_alert = datetime.fromisoformat(created_at.replace("Z", "+00:00"))
                t_recv = datetime.fromisoformat(str(last_recv).replace("Z", "+00:00"))
                delays.append((t_alert - t_recv).total_seconds() * 1000.0)
            except Exception:
                pass

    cur.execute(
        """
        SELECT sys_cpu, sys_memory
        FROM firewall_logs
        WHERE received_at >= ? AND received_at <= ?
          AND sys_cpu IS NOT NULL
          AND sys_memory IS NOT NULL
        """,
                (t0_sql, t1_sql),
    )
    sys_rows = cur.fetchall()
    cpus = [float(r[0]) for r in sys_rows]
    mems = [float(r[1]) for r in sys_rows]

    conn.close()

    return {
        "alerts_created": len(alerts),
        "avg_alert_pipeline_delay_ms": round(statistics.mean(delays), 2) if delays else None,
        "p95_alert_pipeline_delay_ms": round(percentile(delays, 0.95), 2) if delays else None,
        "avg_sys_cpu": round(statistics.mean(cpus), 2) if cpus else None,
        "p95_sys_cpu": round(percentile(cpus, 0.95), 2) if cpus else None,
        "avg_sys_memory": round(statistics.mean(mems), 2) if mems else None,
        "p95_sys_memory": round(percentile(mems, 0.95), 2) if mems else None,
        "detection_source_counts": src_counts,
    }


def aggregate_trials(trials: List[Dict], key: str) -> Dict:
    vals = [float(t[key]) for t in trials if t.get(key) is not None]
    if not vals:
        return {"mean": None, "std": None, "ci95_half_width": None}
    mean = statistics.mean(vals)
    std = statistics.stdev(vals) if len(vals) > 1 else 0.0
    ci95 = 1.96 * (std / math.sqrt(len(vals))) if len(vals) > 1 else 0.0
    return {
        "mean": round(mean, 4),
        "std": round(std, 4),
        "ci95_half_width": round(ci95, 4),
    }


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--profile", required=True)
    ap.add_argument("--trials", type=int, default=5)
    ap.add_argument("--base-url", default="http://localhost:5000")
    ap.add_argument("--timeout", type=float, default=8.0)
    ap.add_argument("--benign-count", type=int, default=30)
    ap.add_argument("--attack-repeat", type=int, default=3)
    ap.add_argument("--burst-count", type=int, default=60)
    ap.add_argument("--request-pause-ms", type=float, default=25.0)
    ap.add_argument("--settle-seconds", type=float, default=8.0)
    ap.add_argument("--expected-latency-ms", type=float, default=120.0)
    ap.add_argument("--timeout-rate-estimate", type=float, default=0.20)
    ap.add_argument("--preview-only", action="store_true")
    ap.add_argument("--progress-every", type=int, default=20)
    ap.add_argument("--max-status0-ratio", type=float, default=0.50)
    ap.add_argument("--max-consecutive-status0", type=int, default=25)
    ap.add_argument("--min-requests-before-abort", type=int, default=40)
    ap.add_argument("--user-agent", default="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
    ap.add_argument("--out-dir", default="research_package/results")
    ap.add_argument("--run-session", default="")
    ap.add_argument("--threatloom-db", default="ThreatLoom/threatloom.db")
    args = ap.parse_args()

    run_session = args.run_session.strip() if args.run_session else datetime.now().strftime("run_%Y%m%d_%H%M%S")

    attacks_per_trial = (len(SQLI_PAYLOADS) + len(XSS_PAYLOADS) + len(MISC_PAYLOADS)) * args.attack_repeat
    requests_per_trial = args.benign_count + attacks_per_trial + args.burst_count
    total_requests = requests_per_trial * args.trials

    expected_req_seconds = requests_per_trial * ((max(0.0, args.request_pause_ms) + max(0.0, args.expected_latency_ms)) / 1000.0)
    worst_req_seconds = requests_per_trial * ((max(0.0, args.request_pause_ms) / 1000.0) + max(0.0, args.timeout))
    tr = min(1.0, max(0.0, args.timeout_rate_estimate))
    stress_req_seconds = requests_per_trial * ((max(0.0, args.request_pause_ms) / 1000.0) + ((1.0 - tr) * (max(0.0, args.expected_latency_ms) / 1000.0) + (tr * max(0.0, args.timeout))))
    expected_trial_seconds = expected_req_seconds + max(0.0, args.settle_seconds)
    worst_trial_seconds = worst_req_seconds + max(0.0, args.settle_seconds)
    stress_trial_seconds = stress_req_seconds + max(0.0, args.settle_seconds)
    expected_total_seconds = expected_trial_seconds * args.trials
    worst_total_seconds = worst_trial_seconds * args.trials
    stress_total_seconds = stress_trial_seconds * args.trials

    print("[PLAN] Benchmark pre-run summary")
    print(f"  profile: {args.profile}")
    print(f"  trials: {args.trials}")
    print(
        "  requests per trial: "
        f"{requests_per_trial} (benign={args.benign_count}, attacks={attacks_per_trial}, burst={args.burst_count})"
    )
    print(f"  total requests: {total_requests}")
    print(
        "  estimated duration: "
        f"~{expected_total_seconds / 60.0:.1f} min expected "
        f"| ~{stress_total_seconds / 60.0:.1f} min stress "
        f"(upper bound ~{worst_total_seconds / 60.0:.1f} min if requests hit timeout)"
    )
    print(
        "  estimate inputs: "
        f"pause={args.request_pause_ms:.1f}ms, expected_latency={args.expected_latency_ms:.1f}ms, "
        f"timeout={args.timeout:.1f}s, timeout_rate_estimate={tr:.2f}, settle={args.settle_seconds:.1f}s/trial"
    )
    print(
        "  fail-fast guards: "
        f"status0_ratio>={args.max_status0_ratio:.2f} (after {args.min_requests_before_abort} reqs) "
        f"or consecutive_status0>={args.max_consecutive_status0}"
    )
    print("  latency basis: client end-to-end wall-clock ms (optional server timing captured when headers are present)")
    print(f"  output session: {run_session}")

    if args.preview_only:
        return

    out_dir = Path(args.out_dir) / run_session / args.profile
    out_dir.mkdir(parents=True, exist_ok=True)
    db_path = Path(args.threatloom_db)

    trial_summaries: List[Dict] = []

    for i in range(1, args.trials + 1):
        t0 = iso_now()
        try:
            rows = run_trial(
                args.base_url.rstrip("/"),
                args.timeout,
                args.user_agent,
                args.benign_count,
                args.attack_repeat,
                args.burst_count,
                args.request_pause_ms,
                args.progress_every,
                args.max_status0_ratio,
                args.max_consecutive_status0,
                args.min_requests_before_abort,
            )
        except RuntimeError as e:
            print(f"[trial {i}] aborted early: {e}")
            rows = []
        # Give async ingestion/detection a small settle window.
        time.sleep(max(0.0, args.settle_seconds))
        t1 = iso_now()

        if not rows:
            break

        summary = summarize(rows)
        soc = collect_soc_window_metrics(db_path, t0, t1)
        merged = {"trial": i, "profile": args.profile, **summary, **soc, "t0": t0, "t1": t1}
        trial_summaries.append(merged)

        with (out_dir / f"trial_{i}_requests.csv").open("w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(
                f,
                fieldnames=["label", "status", "latency_ms", "server_processing_ms", "error_kind"],
            )
            writer.writeheader()
            writer.writerows(rows)

        with (out_dir / f"trial_{i}_summary.json").open("w", encoding="utf-8") as f:
            json.dump(merged, f, indent=2)

    metric_keys = [
        "precision",
        "recall",
        "f1",
        "false_positive_rate",
        "p50_ms",
        "p95_ms",
        "throughput_req_per_sec",
        "avg_alert_pipeline_delay_ms",
        "p95_alert_pipeline_delay_ms",
        "avg_sys_cpu",
        "p95_sys_cpu",
        "avg_sys_memory",
        "p95_sys_memory",
    ]

    aggregate = {k: aggregate_trials(trial_summaries, k) for k in metric_keys}
    aggregate["profile"] = args.profile
    aggregate["trials"] = args.trials
    aggregate["run_session"] = run_session

    with (out_dir / "aggregate_stats.json").open("w", encoding="utf-8") as f:
        json.dump({"trials": trial_summaries, "aggregate": aggregate}, f, indent=2)

    with (out_dir / "aggregate_stats.csv").open("w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["metric", "mean", "std", "ci95_half_width"])
        for k in metric_keys:
            m = aggregate[k]
            writer.writerow([k, m["mean"], m["std"], m["ci95_half_width"]])

    print(json.dumps(aggregate, indent=2))


if __name__ == "__main__":
    main()
