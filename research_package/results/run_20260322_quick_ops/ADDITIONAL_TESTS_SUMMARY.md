# Additional Conductable Tests Summary

Session: run_20260322_quick_ops
Date: 2026-03-22

## 1) Quick Hybrid Probe (profile_c_quick_ops_eval)
Source: profile_c_quick_ops_eval/trial_1_summary.json

- Total requests: 64
- Precision: 1.0000
- Recall: 1.0000
- F1: 1.0000
- False positive rate: 0.0000
- p50 latency: 39.26 ms
- p95 latency: 282.64 ms
- Throughput: 6.30 req/s
- Alerts created: 5
- Alert pipeline delay (proxy, log receipt to alert creation):
  - Mean: 5220.02 ms
  - p95: 7778.23 ms

## 2) Host-Level Resource Probe During Benchmark
Source: system_resource_probe.json

- Samples: 9
- CPU usage:
  - Mean: 18.70%
  - p95: 28.72%
- Memory usage:
  - Mean: 85.08%
  - p95: 85.34%
- Method: host-level performance counters sampled during benchmark execution.

## 3) SQLite Log/Query Micro-Benchmark (50 runs/query)
Source: query_benchmark.json

- recent_200_logs: mean 17.235 ms, p95 22.186 ms
- sqli_high_recent_500: mean 5.603 ms, p95 7.965 ms
- src_ip_time_window: mean 14.158 ms, p95 20.033 ms
- agg_by_attack_type: mean 0.252 ms, p95 0.281 ms

## 4) Response Timing Proxy From Alert-Incident Linkage
Source: response_timing_proxy.json

- Metric: alert_to_incident_creation_delay_ms
- Non-negative pairs: n=33
  - Mean: 3659.40 ms
  - p95: 5354.34 ms
- Negative pairs observed: 223
  - Indicates historical linkage/timestamp inconsistency

## Caveat
These additions are supplemental evidence only. They do not replace the main repeated-trial A/B/C/B-tuned comparison and do not constitute direct mitigation action completion timing.