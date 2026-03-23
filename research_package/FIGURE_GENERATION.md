# Figure Generation Guide

## Prerequisites
- Python 3.9+
- matplotlib installed

Install dependency:
- pip install matplotlib

## Generate Figures
From the research_package directory:
- python generate_figures.py

Outputs are written to:
- research_package/figures/fig3_detection_quality.png
- research_package/figures/fig4_runtime_tradeoff.png
- research_package/figures/fig5_confusion_components.png
- research_package/figures/figure_data_compiled.csv

## Notes
- The script reads summary JSON artifacts for Profiles A, B, and C.
- If mitigation delay values are later measured, add a dedicated mitigation-delay figure in the same folder.
