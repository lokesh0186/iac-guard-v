# IaC-Guard-V: A Verification Framework for LLM-Generated Infrastructure-as-Code Repairs

**Paper**: Under review at IEEE QRS 2026

## Overview

IaC-Guard-V is a verification-centered framework that evaluates LLM-generated Infrastructure-as-Code (IaC) repairs through four verification gates: syntactic validity, target-issue resolution, regression safety, and patch minimality.

**Key findings** from 630 experimental runs across 3 LLM families and 3 repair strategies:
- All models achieve 100% syntactic validity, but only 32–50% pass full verification under single-shot prompting
- Verification-guided iterative repair achieves 68–92% verified-fix rates (statistically significant, p ≤ 0.008)
- An open-source model with verification outperforms the strongest commercial model without it at 1/12th the cost

## Repository Structure

```
iac-guard-v/
├── paper.tex                    # Paper source (LaTeX, IEEE format)
├── paper.pdf                    # Compiled paper
├── README.md                    # This file
├── benchmark/
│   ├── raw/                     # 1,081 Terraform + 2,400 K8s benchmark artifacts
│   ├── selected_manifest.csv    # 50 selected Terraform items
│   ├── selected_manifest_enriched.csv  # With violation class labels
│   ├── k8s_selected_manifest.csv       # 20 selected K8s items
│   ├── k8s_selected_manifest_enriched.csv
│   └── manifest.csv             # Full corpus manifest (3,481 items)
├── scripts/
│   ├── build_benchmark.py       # Benchmark construction (Terraform)
│   ├── build_k8s_benchmark.py   # Benchmark construction (Kubernetes)
│   ├── run_experiment.py        # Main experiment runner
│   ├── run_full_experiments.py  # Orchestrator for all model/method combos
│   ├── run_baseline_checkov.py  # Baseline scanner runs
│   ├── run_k8s_baseline.py      # K8s baseline scanner runs
│   ├── call_bedrock.py          # AWS Bedrock API caller
│   ├── verify_patch.py          # 4-gate verification harness
│   ├── analyze_part1.py         # Results analysis (main tables)
│   ├── analyze_part2.py         # Results analysis (cost, minimality)
│   └── analyze_part3.py         # Results analysis (figures, stats)
├── prompts/
│   ├── plain_v1.txt             # Plain prompting template
│   ├── structured_v1.txt        # Structured prompting template
│   └── retry_v1.txt             # Verification-guided retry template
├── runs/
│   ├── raw/                     # 630 raw LLM responses (JSON)
│   └── patches/                 # 630 extracted patches
├── results/
│   ├── tables/                  # CSV result tables
│   │   ├── all_runs.csv         # Complete results (630 rows)
│   │   ├── main_results_with_ci.csv
│   │   ├── cost_effectiveness.csv
│   │   ├── results_by_violation_class.csv
│   │   ├── statistical_tests.csv
│   │   └── convergence.csv
│   └── figures/                 # Paper figures (PNG)
│       ├── figure1_pipeline.png
│       ├── figure2_hero_vfr.png
│       └── figure3_convergence.png
├── verifier/                    # Verification harness modules
├── baselines/                   # Baseline Checkov outputs
├── scanners/                    # Scanner configuration
└── retrieval/                   # RAG retrieval components
```

## Reproducing Results

### Prerequisites
- Python 3.10+
- Checkov v3.2.517 (`pip install checkov==3.2.517`)
- AWS account with Bedrock access (Claude Opus 4.6, Claude Sonnet 4.6, Llama 4 Maverick)

### Steps

1. **Run baselines**: `python scripts/run_baseline_checkov.py`
2. **Run experiments**: `python scripts/run_full_experiments.py`
3. **Analyze results**: `python scripts/analyze_part1.py && python scripts/analyze_part2.py && python scripts/analyze_part3.py`

## Models Evaluated

| Model | Family | Type |
|-------|--------|------|
| Claude Opus 4.6 | Anthropic | Commercial |
| Claude Sonnet 4.6 | Anthropic | Commercial |
| Llama 4 Maverick 17B | Meta | Open-weight |

## Citation

```bibtex
@inproceedings{chauhan2026iacguardv,
  title={IaC-Guard-V: A Verification Framework for LLM-Generated Infrastructure-as-Code Repairs},
  author={Chauhan, Lokesh},
  booktitle={Proceedings of the IEEE International Conference on Software Quality, Reliability, and Security (QRS)},
  year={2026}
}
```

## License

This research artifact is released for academic reproducibility. The benchmark items are derived from Checkov's open-source test suite (Apache 2.0).
