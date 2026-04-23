#!/usr/bin/env python3
"""
IaC-Guard-V: Full Experiment Execution Script
Runs all experiment sets in order with proper logging and checkpointing.

Usage: python3 run_full_experiments.py
"""
import subprocess
import sys
import os
import json
import time
from datetime import datetime

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCRIPTS = f"{BASE}/scripts"
RESULTS = f"{BASE}/results"
LOGS = f"{BASE}/runs/logs"

os.makedirs(LOGS, exist_ok=True)

# Experiment metadata
EXPERIMENT_META = {
    'experiment_id': f'iac-guard-v-full-{datetime.now().strftime("%Y%m%d-%H%M%S")}',
    'start_time': datetime.now().isoformat(),
    'checkov_version': '3.2.517',
    'prompt_versions': {
        'plain': 'plain_v1.txt',
        'structured': 'structured_v1.txt',
        'retry': 'retry_v1.txt',
    },
    'temperature': 0.0,
    'max_retries_verify_loop': 2,
    'benchmark_items': 50,
    'benchmark_source': 'Checkov test suite (bridgecrewio/checkov)',
}

def run_experiment_set(name, models, methods, max_items=50):
    """Run one experiment set and log results."""
    print(f"\n{'='*70}")
    print(f"EXPERIMENT SET: {name}")
    print(f"Models: {models} | Methods: {methods} | Items: {max_items}")
    print(f"Started: {datetime.now().isoformat()}")
    print(f"{'='*70}")

    cmd = [
        sys.executable, f'{SCRIPTS}/run_experiment.py',
        ','.join(models), ','.join(methods), str(max_items)
    ]
    env = os.environ.copy()
    env['PATH'] = env.get('PATH', '') + ''

    result = subprocess.run(cmd, env=env, capture_output=False)

    print(f"\nCompleted: {datetime.now().isoformat()}")
    print(f"Exit code: {result.returncode}")
    return result.returncode


def main():
    print(f"IaC-Guard-V Full Experiment Suite")
    print(f"Experiment ID: {EXPERIMENT_META['experiment_id']}")
    print(f"Start time: {EXPERIMENT_META['start_time']}")

    # Save experiment metadata
    meta_file = f"{LOGS}/experiment_metadata.json"
    with open(meta_file, 'w') as f:
        json.dump(EXPERIMENT_META, f, indent=2)

    # ============================================================
    # SET A: Core Results — Claude Sonnet 4.6 × all methods
    # This is the primary result table in the paper
    # ============================================================
    rc = run_experiment_set(
        name="A: Core Results (Claude Sonnet 4.6)",
        models=['claude-sonnet-4.6'],
        methods=['plain', 'structured', 'verify_loop'],
        max_items=50,
    )
    if rc != 0:
        print("⚠️  Set A failed. Check logs.")

    # ============================================================
    # SET B: Cross-Model — Llama 4 Maverick × all methods
    # Shows generalization across model families
    # ============================================================
    rc = run_experiment_set(
        name="B: Cross-Model (Llama 4 Maverick)",
        models=['llama4-maverick'],
        methods=['plain', 'structured', 'verify_loop'],
        max_items=50,
    )
    if rc != 0:
        print("⚠️  Set B failed. Check logs.")

    # ============================================================
    # SET C: Strongest Model — Claude Opus 4.6 × verify_loop only
    # Shows best-case performance
    # ============================================================
    rc = run_experiment_set(
        name="C: Strongest Model (Claude Opus 4.6, verify_loop only)",
        models=['claude-opus-4.6'],
        methods=['verify_loop'],
        max_items=50,
    )
    if rc != 0:
        print("⚠️  Set C failed. Check logs.")

    # Save completion metadata
    EXPERIMENT_META['end_time'] = datetime.now().isoformat()
    EXPERIMENT_META['status'] = 'completed'
    with open(meta_file, 'w') as f:
        json.dump(EXPERIMENT_META, f, indent=2)

    print(f"\n{'='*70}")
    print(f"ALL EXPERIMENT SETS COMPLETE")
    print(f"End time: {EXPERIMENT_META['end_time']}")
    print(f"Results: {RESULTS}/tables/all_runs.csv")
    print(f"Metadata: {meta_file}")
    print(f"{'='*70}")


if __name__ == '__main__':
    main()
