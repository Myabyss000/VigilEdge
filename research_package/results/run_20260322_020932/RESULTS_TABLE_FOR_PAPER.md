# Session Results Table (Paper-Ready)

Session: run_20260322_020932  
Trials per profile: 3  
Latency basis: client end-to-end wall-clock ms

## Detection Quality (Mean ± Std)

| Profile | Precision | Recall | F1-score | False Positive Rate |
|---|---:|---:|---:|---:|
| A (signature-only) | 0.6998 ± 0.2600 | 1.0000 ± 0.0000 | 0.8062 ± 0.1678 | 0.6556 ± 0.5680 |
| B (WAF + SOC rules) | 0.6998 ± 0.2600 | 1.0000 ± 0.0000 | 0.8062 ± 0.1678 | 0.6556 ± 0.5680 |
| C (full hybrid) | 0.6970 ± 0.2624 | 1.0000 ± 0.0000 | 0.8039 ± 0.1698 | 0.6667 ± 0.5774 |
| B-tuned | 0.6998 ± 0.2600 | 1.0000 ± 0.0000 | 0.8062 ± 0.1678 | 0.6556 ± 0.5680 |

## Runtime (Mean ± Std)

| Profile | p50 Latency (ms) | p95 Latency (ms) | Throughput (req/s) |
|---|---:|---:|---:|
| A (signature-only) | 28.72 ± 6.14 | 121.56 ± 150.30 | 17.91 ± 8.22 |
| B (WAF + SOC rules) | 32.23 ± 6.52 | 125.35 ± 117.17 | 16.01 ± 6.52 |
| C (full hybrid) | 28.85 ± 4.56 | 117.19 ± 135.47 | 17.56 ± 7.67 |
| B-tuned | 28.15 ± 4.45 | 146.06 ± 177.36 | 16.74 ± 8.02 |

## CI95 Half-Width (selected)

| Profile | Precision CI95 ± | FPR CI95 ± | p50 CI95 ± | p95 CI95 ± |
|---|---:|---:|---:|---:|
| A | 0.2943 | 0.6427 | 6.9461 | 170.0859 |
| B | 0.2943 | 0.6427 | 7.3823 | 132.5908 |
| C | 0.2969 | 0.6533 | 5.1598 | 153.2956 |
| B-tuned | 0.2943 | 0.6427 | 5.0336 | 200.7011 |

## Interpretation Notes

- All profiles reached recall = 1.0000 in this synthetic workload.
- False positive behavior is unstable across trials (large FPR standard deviations and wide CI95), indicating calibration sensitivity.
- Runtime medians are low (tens of milliseconds), but p95 variance is high between trials.
- Mitigation delay, server-side timing headers, and resource metrics are still not populated in this session artifacts.
