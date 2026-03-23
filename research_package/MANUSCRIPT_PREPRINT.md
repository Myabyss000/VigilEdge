# VigilEdge-ThreatLoom: Local-First Hybrid WAF and SOC for Detection, Correlation, and Automated Mitigation

## Abstract
This preprint presents VigilEdge-ThreatLoom, a local security architecture that combines inline web application firewall enforcement with SOC analytics and playbook-driven response. The central design hypothesis is that local deployments can gain operational depth by linking request-time filtering with event-time correlation and bounded mitigation actions. The system is implemented as a practical stack with real dashboards, APIs, and asynchronous processing paths. We provide an evidence-oriented experiment plan to compare three deployment profiles and evaluate quality and performance tradeoffs. The preprint is intentionally artifact-oriented and structured for iterative updates as measured results are added.

## 1. Why This Work Matters
Cloud-native defenses are strong, but not universally deployable. Many teams require local control, private operation, and transparent workflows. A common failure mode in local deployments is overreliance on single-request signatures without broader behavioral context. This work addresses that gap with a hybrid defense pipeline.

## 2. Research Framing
### 2.1 Main Question
Can a local hybrid WAF-SOC architecture provide better practical detection and response outcomes than a signature-only local WAF without unacceptable system overhead?

### 2.2 Claims Scope
The system is a local-first architecture. It is not positioned as a full replacement for globally distributed edge protection.

## 3. Architecture Narrative
### 3.1 WAF Layer
VigilEdge applies inline checks, immediate decisioning, and event emission.

### 3.2 SOC Layer
ThreatLoom ingests events, runs layered analytics, and creates deduplicated alerts/incidents.

### 3.3 Response Layer
Playbooks trigger response actions such as block and rate-limit, with recorded state and revocation controls.

## 4. Detection Pipeline
1. Signature-driven inline checks.
2. Event normalization and metadata enrichment.
3. SOC rule and threshold logic.
4. Behavioral and correlation analysis.
5. Automated response orchestration.

## 5. Evaluation Blueprint
### 5.1 Profiles
- A: signature-only.
- B: WAF plus SOC rules/thresholds.
- C: full hybrid with playbook response.

### 5.2 Traffic Classes
- Benign control traffic.
- SQLi and XSS variants.
- Traversal and command-injection patterns.
- Brute-force and burst traffic.

### 5.3 Metrics
- Precision, recall, F1-score.
- False positive rate (FPR).
- Detection and mitigation delay.
- p50/p95 latency and throughput.

## 6. What Is Ready Now
- Architecture and manuscript structure.
- Reproducibility protocol.
- Submission checklist.
- BibTeX reference starter set.

## 7. What Must Be Filled Before Final Submission
- Mitigation delay measurements.
- Multi-run confidence intervals.
- Venue-specific formatting.
- Expanded related work citations.
- Final data/code availability statements.

## 8. Responsible Use
All testing must be performed on authorized systems and defensive lab targets only.

## 9. Living Result Tables
### 9.1 Detection Quality
| Profile | Precision | Recall | F1-score | False Positive Rate |
|---|---:|---:|---:|---:|
| A | 0.7619 | 1.0000 | 0.8649 | 0.3750 |
| B | 0.5455 | 1.0000 | 0.7059 | 1.0000 |
| C | 0.7619 | 1.0000 | 0.8649 | 0.3750 |

### 9.2 Performance
| Profile | p50 (ms) | p95 (ms) | Throughput (req/s) | Mitigation Delay (ms) |
|---|---:|---:|---:|---:|
| A | 42.89 | 263.51 | 12.84 | N/A |
| B | 45.76 | 96.96 | 17.19 | TBD |
| C | 42.57 | 259.39 | 13.36 | TBD |

Measured run artifacts:
- `research_package/benchmark_profile_a_signature_only_requests.csv`
- `research_package/benchmark_profile_a_signature_only_summary.json`
- `research_package/benchmark_profile_b_waf_plus_soc_rules_requests.csv`
- `research_package/benchmark_profile_b_waf_plus_soc_rules_summary.json`
- `research_package/benchmark_profile_c_requests.csv`
- `research_package/benchmark_profile_c_summary.json`

Observation:
- Profile B overblocked benign requests in this run (FPR = 1.0000), indicating mis-tuned policy behavior that must be discussed in the final analysis.

### 9.3 Results Interpretation
The measured runs support a cautious but meaningful conclusion. Under this workload, all profiles achieved full recall, but quality diverged on false positives. Profiles A and C showed the strongest balance, while Profile B entered an overblocking regime that reduced precision despite maintaining recall.

Performance values must be interpreted together with detection quality. Profile B appears faster at tail latency and throughput, yet this occurred while blocking nearly everything, including benign requests. This is not a favorable security-performance tradeoff; it is evidence that policy tuning dominates practical effectiveness.

For this preprint, the key takeaway is that hybrid local security is viable, but only when configuration governance is treated as a first-class research variable. The next iteration should report tuned Profile B reruns and repeated-trial confidence intervals.

## 10. Camera-Ready Action Checklist
- Measure and fill mitigation delay for Profiles B and C.
- Add repeated-trial mean and standard deviation for all primary metrics.
- Add a tuned Profile B rerun with documented threshold changes.
- Expand related work with current, venue-appropriate citations.
- Finalize data and code availability statements with concrete links.
- Confirm all claims in abstract and summary sections remain evidence-bounded.

## 11. Artifact Links
- Full manuscript: [research_package/MANUSCRIPT.md](research_package/MANUSCRIPT.md)
- IEEE-oriented version: [research_package/MANUSCRIPT_IEEE_SUBMISSION.md](research_package/MANUSCRIPT_IEEE_SUBMISSION.md)
- Experiment protocol: [research_package/EXPERIMENT_PROTOCOL.md](research_package/EXPERIMENT_PROTOCOL.md)
- Command runbook: [research_package/EXPERIMENT_RUNBOOK_COMMANDS.md](research_package/EXPERIMENT_RUNBOOK_COMMANDS.md)
- Submission checklist: [research_package/SUBMISSION_CHECKLIST.md](research_package/SUBMISSION_CHECKLIST.md)
- References: [research_package/references.bib](research_package/references.bib)
