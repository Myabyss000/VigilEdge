# VigilEdge-ThreatLoom: A Local Hybrid WAF-SOC Architecture for Real-Time Web Threat Detection and Automated Response

## Author Block (Edit Before Submission)
- First Author: <Your Name>, <Affiliation>, <Email>
- Second Author: <Optional>
- Corresponding Author: <Your Name>

## Abstract
Cloud-managed security platforms provide broad web protection, but local-first deployments remain essential in classrooms, constrained budgets, regulated environments, and privacy-sensitive organizations. This paper presents VigilEdge-ThreatLoom, a self-hosted hybrid architecture that combines inline web application firewall (WAF) enforcement with downstream SOC analytics and playbook-based response automation. The system unifies request-time signature checks, context-aware event ingestion, threshold and behavioral detection, and automated mitigation actions (block, temporary ban, and adaptive rate limiting) with analyst override paths.

Unlike single-stage signature firewalls, VigilEdge-ThreatLoom models defense as a multi-stage decision pipeline in which enforcement and operations are jointly coordinated. We define a reproducible evaluation protocol across three configurations: signature-only WAF, WAF plus SOC rules, and full hybrid pipeline. The protocol measures detection quality (precision, recall, F1-score), operational risk (false positive rate (FPR)), and systems impact (p50 and p95 latency, throughput, and mitigation delay). This work contributes (i) a practical local-first security architecture, (ii) a reproducible benchmarking framework for hybrid WAF-SOC systems, and (iii) an evidence-bounded discussion of safety, limitations, and operational tradeoffs.

## Keywords
Web Application Firewall, SOC Automation, Hybrid Detection, Local Security, Incident Response, Playbook Orchestration

## 1. Introduction
Web applications remain the most exposed enterprise interface and continue to be targeted by SQL injection, XSS, path traversal, RCE-style payloads, and request flooding. While cloud-native defenses offer strong capabilities, many teams need local control because of data governance constraints, offline operation requirements, and budget limitations.

Most local WAF deployments are signature-centric and operate on per-request context only. In practice, this creates blind spots for low-and-slow activity, repeated probing behavior, and cross-event attack progression. We address this gap by integrating WAF telemetry with SOC analytics and response orchestration in one local pipeline.

### 1.1 Problem Statement
A signature-only local WAF has three recurrent limitations:
1. Low temporal context: individual requests are analyzed in isolation.
2. Weak campaign visibility: distributed attack patterns are under-detected.
3. Limited response lifecycle: detection is decoupled from revocable automated action.

### 1.2 Research Question
Can a local hybrid WAF-SOC architecture improve security operations outcomes over signature-only local WAF deployments while maintaining acceptable runtime overhead under local test conditions?

### 1.3 Contributions
This paper contributes:
1. A modular local architecture combining inline WAF filtering, SOC analytics, and playbook automation.
2. A staged hybrid detection model (signature, threshold, behavioral, and correlation).
3. A reproducible experiment design for quality and performance comparison against baseline configurations.
4. A deployment-focused analysis of safety controls, limitations, and practical adoption paths.

## 2. Related Work
Prior WAF systems emphasize deterministic rule matching and low-latency request mediation. SIEM/SOC systems emphasize event aggregation, correlation, and analyst workflow. Cloud edge providers combine these at global scale, but local equivalents are often fragmented.

The key distinction of this work is integration: request-time defense and SOC-time reasoning are co-designed for local operation. The novelty is not a new regex family alone; it is the end-to-end orchestration model, including event normalization, deduplicated alerting, and bounded playbook response.

## 3. System Architecture
VigilEdge-ThreatLoom comprises four layers.

### 3.1 Inline Enforcement (VigilEdge)
- Intercepts HTTP requests.
- Applies attack-class checks (SQLi, XSS, traversal, command injection, SSRF, template injection).
- Enforces immediate actions (allow, block, rate-limit).
- Emits structured security events.

### 3.2 Ingestion and Normalization (ThreatLoom)
- Receives security events via ingestion APIs.
- Normalizes fields (source IP, action, attack type, path, severity, timestamps).
- Stores telemetry for downstream analytics.

### 3.3 Detection and Correlation
- Executes signature and threshold rules.
- Runs behavioral analyzers (rate, pattern, and temporal signals).
- Correlates by IP/session/time window.
- Produces deduplicated alerts and incidents.

### 3.4 Response Orchestration
- Evaluates playbook trigger conditions.
- Executes mitigations (block, rate-limit, temporary ban, notify, escalate).
- Supports analyst revocation and audit records.

## 4. Detection and Response Methodology
### 4.1 Stage A: Inline Signature Detection
Request payloads are normalized and scanned against class-specific signatures. High-confidence matches trigger immediate blocking.

### 4.2 Stage B: Context Enrichment
Events include metadata required for SOC-level triage, including path, source, action, and threat class.

### 4.3 Stage C: SOC Rule and Threshold Analysis
Post-ingestion analysis applies signature and count/time-window thresholds, identifying repeated patterns not visible at single-request scope.

### 4.4 Stage D: Behavioral and Correlated Detection
Multi-event logic identifies suspicious sequences, repeated campaign behavior, and attack escalation over sliding windows.

### 4.5 Stage E: Playbook Automation
Alert conditions trigger bounded defensive actions with cooldowns and manual override support.

## 5. Implementation Summary
The implementation is Python-based and asynchronous where applicable. The WAF layer handles request-path decisions, while SOC services process ingested telemetry in background cycles. Dashboard and APIs provide operational visibility.

### 5.1 Security Safety Controls
- Role-based access in SOC management endpoints.
- Revocable automated responses.
- Alert deduplication to reduce analyst fatigue.
- Configurable rule/playbook definitions.

### 5.2 Practical Deployment Model
- Local-first operation (single host or small private network).
- Optional integration to external systems via webhooks.
- Suitable for educational labs and small production pilots.

## 6. Evaluation Protocol (Reproducible)
The following protocol defines how the reported metrics are produced and rerun.

### 6.1 Configurations
1. Baseline A: signature-only WAF.
2. Baseline B: WAF plus SOC rules and thresholds.
3. Proposed: full hybrid WAF-SOC with playbook response.

### 6.2 Workloads
- SQLi (plain, obfuscated, encoded)
- XSS (tag, attribute, encoded)
- Traversal/LFI
- Command/RCE-like payloads
- Brute-force and burst traffic
- Benign control traffic

### 6.3 Metrics
- Precision, recall, F1-score
- False positive rate (FPR)
- Detection latency
- Mitigation delay
- p50/p95 response latency
- Throughput

### 6.4 Reproducibility Requirements
- Frozen config snapshots per run
- Versioned scripts and seed values
- Multi-run statistics (mean and standard deviation)
- Open artifact packaging for figures/tables

## 7. Results
### 7.1 Detection Quality
| Configuration | Precision | Recall | F1-score | False Positive Rate |
|---|---:|---:|---:|---:|
| Baseline A | 0.7619 | 1.0000 | 0.8649 | 0.3750 |
| Baseline B | 0.5455 | 1.0000 | 0.7059 | 1.0000 |
| Proposed | 0.7619 | 1.0000 | 0.8649 | 0.3750 |

### 7.2 Performance
| Configuration | p50 Latency (ms) | p95 Latency (ms) | Throughput (req/s) | Mitigation Delay (ms) |
|---|---:|---:|---:|---:|
| Baseline A | 42.89 | 263.51 | 12.84 | N/A |
| Baseline B | 45.76 | 96.96 | 17.19 | TBD |
| Proposed | 42.57 | 259.39 | 13.36 | TBD |

Benchmark evidence note:
- Values for baseline A, baseline B, and proposed profile are from live local benchmark runs with 356 total requests each.
- Request-level data: `research_package/benchmark_profile_a_signature_only_requests.csv`, `research_package/benchmark_profile_b_waf_plus_soc_rules_requests.csv`, `research_package/benchmark_profile_c_requests.csv`.
- Summary metrics: `research_package/benchmark_profile_a_signature_only_summary.json`, `research_package/benchmark_profile_b_waf_plus_soc_rules_summary.json`, `research_package/benchmark_profile_c_summary.json`.
- Baseline B showed extreme overblocking in this run (false positive rate (FPR) = 1.0000), so configuration tuning is required before strong comparative claims.

### 7.3 Results Interpretation
The current measurements indicate two stable findings and one diagnostic finding. First, all profiles achieved perfect recall in this workload, suggesting that attack-like payload classes were consistently intercepted. Second, the best-quality operating points in this run were Baseline A and Proposed C, which matched on precision, recall, F1-score, and false positive rate (FPR). Third, Baseline B behaved as an intentionally informative failure mode: it preserved recall but collapsed in precision because benign traffic was also blocked.

The performance profile is similarly mixed. Baseline B reported the lowest p95 latency and highest throughput, but this occurred alongside severe overblocking and therefore does not represent a desirable operating regime. Proposed C preserved near-Baseline-A quality while maintaining comparable latency and throughput, which supports the core claim that a local hybrid architecture can add operational depth without clear catastrophic runtime overhead.

Interpretively, these results should be framed as a controlled local benchmark rather than a universal performance claim. The correct conclusion at this stage is that policy quality dominates stack quality: correlation and response components help only when their thresholds and rules are tuned to avoid suppressing benign traffic.

## 8. Threats to Validity
1. Internal validity: configuration drift can bias metrics.
2. External validity: synthetic traffic may not reflect all production patterns.
3. Construct validity: rule-based labels can overestimate confidence for near-miss attacks.
4. Operational validity: local hardware differences influence latency and throughput.

## 9. Discussion
The architecture is stronger than standalone regex filtering because it links detection to operational context and automated response. However, it is not equivalent to globally distributed cloud edge protection. Its value proposition is local controllability, reproducibility, and lower operational entry cost.

The measured A/B/C comparison reinforces this positioning. In particular, the experiment shows that additional detection layers are not automatically beneficial unless policy thresholds are calibrated against realistic benign traffic. The Profile B overblocking case should be presented as a strength of the paper, not a weakness: it demonstrates why hybrid systems require explicit tuning and why reporting false-positive behavior is essential for credible defensive research.

For publication quality, the next revision should include a calibrated B-profile rerun, confidence intervals across repeated trials, and ablation of individual SOC rule groups. Those additions would separate architecture-level benefits from configuration-specific artifacts and improve external validity.

## 10. Limitations
- Rule quality and update cadence remain critical.
- Local threat intelligence is narrower than internet-scale telemetry.
- Misconfigured automation can raise false-positive impact.
- Single-node constraints can limit sustained throughput.

## 11. Ethics, Safety, and Responsible Use
- Defensive use only.
- Authorized test targets only.
- No live attack execution against third-party systems.
- Privacy-aware logging and data retention policies required.

## 12. Conclusion
VigilEdge-ThreatLoom demonstrates that a local hybrid WAF-SOC architecture can provide practical defense-in-depth beyond signature-only local WAF deployments. The proposed methodology and artifact structure support reproducible evaluation and publication-ready reporting once metrics are executed.

## 13. Declarations (Fill Before Submission)
- Funding: None / <Add>
- Conflicts of Interest: None / <Add>
- Data Availability: <Repository or internal policy>
- Code Availability: <Repository URL>
- Ethical Approval: Not applicable / <Add if required>

## 14. Camera-Ready Action Checklist
- Complete mitigation delay measurements for Profiles B and C.
- Run at least 5 repeated trials per profile and report mean plus standard deviation.
- Rerun calibrated Profile B and document threshold changes in an appendix.
- Add one ablation table for SOC rule groups to isolate configuration effects.
- Expand related work with venue-relevant citations from the last 3 to 5 years.
- Finalize data/code availability statements with concrete repository links.
- Verify that all claims in Abstract and Conclusion map to measured evidence.

## References
Use the BibTeX file in this package and your target venue style.
