# Figure Captions and Results Pack

## Scope
This file contains publication-ready figure captions, plotting inputs, and narrative anchors aligned with measured A/B/C results.

## Source Artifacts
- benchmark_profile_a_signature_only_summary.json
- benchmark_profile_b_waf_plus_soc_rules_summary.json
- benchmark_profile_c_summary.json
- benchmark_profile_a_signature_only_requests.csv
- benchmark_profile_b_waf_plus_soc_rules_requests.csv
- benchmark_profile_c_requests.csv

## Figure 1: System Architecture Overview
Caption:
VigilEdge-ThreatLoom architecture with four layers: inline enforcement, ingestion and normalization, SOC detection and correlation, and playbook-driven response. The design connects request-path controls with event-path analytics to support bounded local automation.

Figure content checklist:
- WAF ingress and policy decision nodes
- Event emitter and normalized ingestion path
- SOC rule, threshold, and behavioral stages
- Playbook trigger, action, and revocation loop

## Figure 2: Detection and Response Pipeline Sequence
Caption:
End-to-end detection pipeline from HTTP request interception through event enrichment, SOC correlation, alert generation, and mitigation action execution. Dashed transitions represent analyst override and rollback controls.

Figure content checklist:
- Request path decision branch (allow, block, rate-limit)
- Async SOC processing lane
- Correlation window stage
- Action execution and audit trail stage

## Figure 3: Detection Quality by Profile
Caption:
Detection quality comparison for Profiles A, B, and C. Recall is identical across profiles (1.0000), while precision and F1-score diverge due to Profile B overblocking. Profiles A and C share the best quality balance in this run.

Data to plot:
| Profile | Precision | Recall | F1-score | FPR |
|---|---:|---:|---:|---:|
| A | 0.7619 | 1.0000 | 0.8649 | 0.3750 |
| B | 0.5455 | 1.0000 | 0.7059 | 1.0000 |
| C | 0.7619 | 1.0000 | 0.8649 | 0.3750 |

Recommended chart:
- Grouped bars for Precision, Recall, F1-score
- Overlay point or secondary axis for FPR

## Figure 4: Runtime Tradeoff by Profile
Caption:
Runtime performance comparison for Profiles A, B, and C. Profile B reports higher throughput and lower p95 latency but does so under severe overblocking (FPR = 1.0000), indicating policy miscalibration rather than a robust performance advantage.

Data to plot:
| Profile | p50 ms | p95 ms | Throughput req/s |
|---|---:|---:|---:|
| A | 42.89 | 263.51 | 12.84 |
| B | 45.76 | 96.96 | 17.19 |
| C | 42.57 | 259.39 | 13.36 |

Recommended chart:
- Dual-axis chart: latency bars (p50, p95) plus throughput line

## Figure 5: Confusion Matrix Comparison
Caption:
Confusion statistics for A/B/C profiles. Profile B produces zero true negatives and elevated false positives, confirming an overblocking regime despite unchanged recall.

Data to plot:
| Profile | TP | FP | FN | TN |
|---|---:|---:|---:|---:|
| A | 96 | 30 | 0 | 50 |
| B | 96 | 80 | 0 | 0 |
| C | 96 | 30 | 0 | 50 |

Recommended chart:
- Heatmaps per profile or stacked bars for TP/FP/FN/TN

## Figure 6: Mitigation Delay Placeholder
Caption:
Mitigation delay by profile, to be filled after delay instrumentation is added to response action timestamps.

Required data fields:
- alert_created_at
- action_started_at
- action_completed_at

Formula:
mitigation_delay_ms = action_completed_at - alert_created_at

## Results Narrative Anchors
- Anchor A: All profiles maintain recall at 1.0000 in current workload.
- Anchor B: A and C maintain identical precision/F1-score and FPR in this run.
- Anchor C: B demonstrates policy overblocking with FPR = 1.0000.
- Anchor D: Runtime gains without quality retention are not accepted as favorable outcomes.

## Camera-Ready Figure Checklist
- Use vector output (PDF, SVG, or EPS) where possible.
- Keep axis labels and units explicit.
- Use consistent color mapping for A/B/C across all plots.
- Ensure caption states the main finding and caveat.
- Cross-reference figure numbers in manuscript body.
