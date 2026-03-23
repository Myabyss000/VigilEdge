# Final Submission Bundle Order

## 1. Core Manuscript Files
1. MANUSCRIPT_IEEE_SUBMISSION.tex
2. references.bib
3. MANUSCRIPT_IEEE_SUBMISSION.md (editorial source of record)

## 2. Reproducibility and Methods
1. EXPERIMENT_PROTOCOL.md
2. EXPERIMENT_RUNBOOK_COMMANDS.md
3. run_profile_benchmark.ps1
4. run_profile_c_benchmark.ps1

## 3. Measured Result Artifacts
1. benchmark_profile_a_signature_only_summary.json
2. benchmark_profile_b_waf_plus_soc_rules_summary.json
3. benchmark_profile_c_summary.json
4. benchmark_profile_a_signature_only_requests.csv
5. benchmark_profile_b_waf_plus_soc_rules_requests.csv
6. benchmark_profile_c_requests.csv

## 4. Visual and Analysis Assets
1. FIGURE_CAPTIONS_RESULTS_PACK.md
2. Architecture figure source file (to add)
3. Detection quality chart (to add)
4. Runtime tradeoff chart (to add)
5. Confusion matrix chart (to add)

## 5. Compliance and Readiness
1. SUBMISSION_CHECKLIST.md
2. NEXT_ACTIONS.md
3. LICENSE

## 6. Packaging Sequence
1. Freeze manuscript text and metric tables.
2. Generate final figures and update figure references.
3. Re-run checklist and mark remaining items complete.
4. Export camera-ready PDF from IEEE template.
5. Build a single zip containing manuscript, bib, figures, and measured artifacts.

## 7. Zip Layout Recommendation
- /paper
  - MANUSCRIPT_IEEE_SUBMISSION.tex
  - references.bib
  - camera_ready.pdf
- /figures
  - fig1_architecture.pdf
  - fig2_pipeline.pdf
  - fig3_detection_quality.pdf
  - fig4_runtime_tradeoff.pdf
  - fig5_confusion_matrix.pdf
- /artifacts
  - benchmark_profile_a_signature_only_summary.json
  - benchmark_profile_b_waf_plus_soc_rules_summary.json
  - benchmark_profile_c_summary.json
  - benchmark_profile_a_signature_only_requests.csv
  - benchmark_profile_b_waf_plus_soc_rules_requests.csv
  - benchmark_profile_c_requests.csv
- /methods
  - EXPERIMENT_PROTOCOL.md
  - EXPERIMENT_RUNBOOK_COMMANDS.md

## 8. Final Pre-Upload Gate
- Confirm no placeholder text remains in author block or acknowledgments.
- Confirm all table and figure references resolve.
- Confirm claims in abstract and conclusion are evidence-matched.
- Confirm anonymization if venue is double-blind.
- Confirm PDF metadata (title, authors, keywords) is correct.
