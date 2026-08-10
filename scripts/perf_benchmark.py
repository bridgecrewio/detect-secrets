#!/usr/bin/env python3
"""
Performance benchmark for detect-secrets.

Scans a target directory N times and reports wall time statistics,
comparing against a saved baseline if available.

Usage:
    python scripts/perf_benchmark.py [--target PATH] [--runs N] [--modules M]
    python scripts/perf_benchmark.py --help

Examples:
    # Benchmark 3 modules, 3 runs
    python scripts/perf_benchmark.py --modules 3 --runs 3

    # Benchmark specific path
    python scripts/perf_benchmark.py --target ../synthetic-code-repo/src/module_000/

    # Save result as new baseline
    python scripts/perf_benchmark.py --save-baseline
"""
from __future__ import annotations

import argparse
import json
import statistics
import subprocess
import sys
import time
from pathlib import Path

REPO_ROOT = Path(__file__).parent.parent  # detect-secrets/
SYNTHETIC_REPO = REPO_ROOT.parent / 'synthetic-code-repo'
BASELINES_DIR = REPO_ROOT / 'baselines'
DETECT_SECRETS_BIN = REPO_ROOT / '.venv-perf' / 'bin' / 'detect-secrets'


def get_module_paths(n_modules: int) -> list[Path]:
    """Return paths to the first N modules in synthetic-code-repo/src/."""
    src = SYNTHETIC_REPO / 'src'
    if not src.exists():
        print(f'ERROR: synthetic-code-repo not found at {SYNTHETIC_REPO}', file=sys.stderr)
        sys.exit(1)
    modules = sorted(src.iterdir())[:n_modules]
    return modules


def run_scan(target_paths: list[Path]) -> tuple[float, int]:
    """
    Run detect-secrets scan on target_paths.
    Returns (wall_time_seconds, finding_count).

    IMPORTANT: Must run with cwd=REPO_ROOT.parent (cas-meta/) so detect-secrets
    can resolve files correctly outside the detect-secrets git boundary.
    """
    cmd = [
        str(DETECT_SECRETS_BIN),
        'scan',
        '--all-files',
        # Pin filter configuration explicitly so benchmark results (and finding
        # counts) don't depend on which optional packages (e.g. gibberish-detector)
        # happen to be pip-installed in the venv. The gibberish filter is an ML
        # heuristic that can silently suppress real findings and must not be an
        # implicit, environment-dependent part of benchmark/parity measurements.
        '--disable-filter', 'detect_secrets.filters.gibberish.should_exclude_secret',
    ] + [str(p) for p in target_paths]

    start = time.monotonic()
    result = subprocess.run(cmd, capture_output=True, text=True, check=False,
                            cwd=str(REPO_ROOT.parent))
    elapsed = time.monotonic() - start

    finding_count = 0
    if result.stdout.strip():
        try:
            data = json.loads(result.stdout)
            for secrets in data.get('results', {}).values():
                finding_count += len(secrets)
        except json.JSONDecodeError:
            pass

    return elapsed, finding_count


def load_baseline() -> dict | None:
    """Load the saved timing baseline if it exists."""
    baseline_file = BASELINES_DIR / 'perf-benchmark-baseline.json'
    if baseline_file.exists():
        with open(baseline_file) as f:
            return json.load(f)
    return None


def save_baseline(result: dict) -> None:
    """Save benchmark result as the new baseline."""
    BASELINES_DIR.mkdir(exist_ok=True)
    baseline_file = BASELINES_DIR / 'perf-benchmark-baseline.json'
    with open(baseline_file, 'w') as f:
        json.dump(result, f, indent=2)
    print(f'Saved baseline to {baseline_file}')


def main() -> None:
    parser = argparse.ArgumentParser(description='detect-secrets performance benchmark')
    parser.add_argument('--target', type=Path, help='Target directory to scan (overrides --modules)')
    parser.add_argument('--modules', type=int, default=3, help='Number of synthetic-code-repo modules to scan (default: 3)')
    parser.add_argument('--runs', type=int, default=3, help='Number of benchmark runs (default: 3)')
    parser.add_argument('--save-baseline', action='store_true', help='Save result as new baseline')
    args = parser.parse_args()

    if args.target:
        target_paths = [args.target]
        scope_desc = str(args.target)
    else:
        target_paths = get_module_paths(args.modules)
        scope_desc = f'{args.modules} modules from synthetic-code-repo'

    print(f'Benchmarking detect-secrets on: {scope_desc}')
    print(f'Runs: {args.runs}')
    print(f'Binary: {DETECT_SECRETS_BIN}')
    print()

    times = []
    finding_counts = []

    for i in range(args.runs):
        elapsed, count = run_scan(target_paths)
        times.append(elapsed)
        finding_counts.append(count)
        print(f'  Run {i+1}/{args.runs}: {elapsed:.2f}s  ({count} findings)')

    mean_time = statistics.mean(times)
    median_time = statistics.median(times)
    min_time = min(times)

    print()
    print('Results:')
    print(f'  Mean:   {mean_time:.2f}s')
    print(f'  Median: {median_time:.2f}s')
    print(f'  Min:    {min_time:.2f}s')
    print(f'  Findings (last run): {finding_counts[-1]}')

    result = {
        'scope': scope_desc,
        'runs': args.runs,
        'times': times,
        'mean': mean_time,
        'median': median_time,
        'min': min_time,
        'findings': finding_counts[-1],
    }

    # Compare against baseline
    baseline = load_baseline()
    if baseline:
        baseline_mean = baseline.get('mean', 0)
        if baseline_mean > 0:
            improvement = (baseline_mean - mean_time) / baseline_mean * 100
            sign = '+' if improvement > 0 else ''
            print()
            print(f'vs Baseline ({baseline.get("scope", "unknown")}):')
            print(f'  Baseline mean: {baseline_mean:.2f}s')
            print(f'  Current mean:  {mean_time:.2f}s')
            print(f'  Improvement:   {sign}{improvement:.1f}%')
    else:
        print()
        print('No baseline found. Run with --save-baseline to save current result.')

    if args.save_baseline:
        save_baseline(result)


if __name__ == '__main__':
    main()
