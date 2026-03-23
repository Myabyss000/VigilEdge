# Experiment Protocol for VigilEdge-ThreatLoom

## 1. Goal
Produce reproducible, publication-grade metrics for detection quality and runtime overhead.

## 2. Fixed Configurations
Define and version three profiles:
1. profile_a_signature_only
2. profile_b_waf_plus_soc_rules
3. profile_c_full_hybrid

Store each profile as immutable snapshots in a config folder and reference commit IDs.

## 3. Dataset Design
Create a labeled corpus with classes:
- benign
- sqli
- xss
- traversal
- command_injection
- brute_force
- flood

For each class, include multiple encoding/evasion styles.

## 4. Traffic Generation
Run request replay in fixed phases:
1. warmup phase
2. benign baseline phase
3. mixed attack phase
4. burst/flood phase
5. cooldown phase

Record exact request counts and timing parameters.

## 5. Metrics to Compute
- TP, FP, TN, FN
- Precision
- Recall
- F1-score
- False positive rate (FPR)
- p50 and p95 request latency
- Throughput (requests per second)
- Detection delay (request timestamp to alert timestamp)
- Mitigation delay (alert timestamp to response activation timestamp)

## 6. Run Plan
For each profile:
1. Execute at least 5 independent runs.
2. Keep hardware and OS fixed.
3. Reset state between runs (db, cache, blocklists if required).
4. Export raw logs and summary CSV.

## 7. Analysis
For every metric, report:
- mean
- standard deviation
- min/max

Add confusion matrices for each profile.

## 8. Artifact Packaging
Produce a release folder containing:
- config snapshots
- replay scripts
- raw logs
- processed CSVs
- generated plots
- manuscript tables

## 9. Reproducibility Checklist
- deterministic seeds set
- run commands documented
- commit hash recorded
- environment dependencies pinned
- runtime machine profile captured
- startup path documented (manual and one-command launcher)

## 10. Deployment Reproducibility Path
To reduce setup drift, prefer scripted startup for repeated runs.

Recommended local startup path (Windows):
1. Run `deploy_oneclick.ps1` from repository root.
2. Verify service ports (`5000`, `8443`, `8080`, optionally `5001`).
3. Record launcher mode (`full` or `custom`) in run metadata.

Fallback path:
1. Use manual per-service startup sequence.
2. Record each command and environment override in artifact notes.

## 11. Suggested Figure Outputs
1. Architecture diagram
2. Detection quality bar chart
3. Latency distribution plot
4. Mitigation timeline sequence diagram
