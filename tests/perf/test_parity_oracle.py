"""
Parity oracle: scans secrets-examples/ and asserts findings match the golden snapshot.

This test MUST pass before and after every optimization. Any difference in findings
indicates a regression — the optimization must be reverted.

Run with:
    pytest tests/perf/test_parity_oracle.py -v
"""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).parent.parent.parent  # detect-secrets/
SECRETS_EXAMPLES = REPO_ROOT.parent / 'secrets-examples'
GOLDEN_SNAPSHOT = REPO_ROOT / 'baselines' / 'parity_snapshot.json'
DETECT_SECRETS_BIN = REPO_ROOT / '.venv-perf' / 'bin' / 'detect-secrets'


def _scan_secrets_examples() -> list[dict]:
    """Run detect-secrets scan on secrets-examples/ and return normalized findings.

    IMPORTANT: The subprocess must run with cwd=REPO_ROOT.parent (cas-meta/) because
    detect-secrets uses the CWD to resolve git boundaries. When run from detect-secrets/,
    the tool finds 0 results because secrets-examples/ is outside that git repo.

    Output format (standard detect-secrets):
        {"results": {"filename": [{"line_number": ..., "type": ...}, ...]}}
    """
    # Run from cas-meta/ so detect-secrets can see secrets-examples/ correctly
    cwd = REPO_ROOT.parent

    result = subprocess.run(
        [
            str(DETECT_SECRETS_BIN),
            'scan',
            '--all-files',
            # Pin filter configuration explicitly so results don't depend on which
            # optional packages (e.g. gibberish-detector) happen to be pip-installed.
            # The gibberish filter is an ML heuristic that can silently suppress real
            # findings — it must NOT be part of the canonical parity baseline.
            # See: incident where 37 findings were silently lost when this filter
            # auto-activated due to gibberish-detector being present in the venv.
            '--disable-filter', 'detect_secrets.filters.gibberish.should_exclude_secret',
            str(SECRETS_EXAMPLES),
        ],
        capture_output=True,
        text=True,
        check=False,
        cwd=str(cwd),
    )
    if result.returncode != 0 and not result.stdout.strip():
        pytest.fail(f'detect-secrets scan failed:\n{result.stderr}')

    try:
        data = json.loads(result.stdout)
    except json.JSONDecodeError as e:
        pytest.fail(f'Failed to parse detect-secrets output as JSON: {e}\nOutput: {result.stdout[:500]}')

    findings = []
    # Standard detect-secrets format: results is a dict of filename -> list of secrets
    for fname, secrets in data.get('results', {}).items():
        for s in secrets:
            findings.append({
                'file': fname,
                'line': s['line_number'],
                'type': s['type'],
            })

    findings.sort(key=lambda x: (x['file'], x['line'], x['type']))
    return findings


@pytest.fixture(scope='session')
def current_findings():
    """Session-scoped fixture: scan once, reuse across all tests."""
    return _scan_secrets_examples()


@pytest.fixture(scope='session')
def golden_findings():
    """Load the golden snapshot from baselines/.

    The snapshot format (as produced by the normalization step that generates
    parity_snapshot.json) is a flat list of dicts already using the same keys
    as _scan_secrets_examples(): [{"file": ..., "line": ..., "type": ...}, ...]
    Returns the normalized list of dicts with keys: file, line, type.
    """
    if not GOLDEN_SNAPSHOT.exists():
        pytest.fail(
            f'Golden snapshot not found at {GOLDEN_SNAPSHOT}. '
            'Run Task 0 (environment setup) first to generate it.'
        )
    with open(GOLDEN_SNAPSHOT) as f:
        data = json.load(f)

    # Support both the flat list format ({"file", "line", "type"}) and a
    # legacy wrapped format ({"findings": [{"filename", "line_number", "type"}]})
    # for backwards compatibility with older snapshots.
    raw = data.get('findings', data) if isinstance(data, dict) else data
    findings = [
        {
            'file': s.get('file', s.get('filename')),
            'line': s.get('line', s.get('line_number')),
            'type': s['type'],
        }
        for s in raw
    ]
    findings.sort(key=lambda x: (x['file'], x['line'], x['type']))
    return findings


def test_parity_oracle_matches_snapshot(current_findings, golden_findings):
    """
    Core parity test: current findings must exactly match the golden snapshot.

    If this test fails after an optimization, the optimization introduced a regression
    and must be reverted or fixed before proceeding.
    """
    current_set = {(f['file'], f['line'], f['type']) for f in current_findings}
    golden_set = {(f['file'], f['line'], f['type']) for f in golden_findings}

    missing = golden_set - current_set
    extra = current_set - golden_set

    errors = []
    if missing:
        errors.append(f'MISSING {len(missing)} findings (regression):')
        for item in sorted(missing)[:20]:
            errors.append(f'  - {item[0]}:{item[1]} [{item[2]}]')
        if len(missing) > 20:
            errors.append(f'  ... and {len(missing) - 20} more')

    if extra:
        errors.append(f'EXTRA {len(extra)} findings (new detections or false positives):')
        for item in sorted(extra)[:20]:
            errors.append(f'  + {item[0]}:{item[1]} [{item[2]}]')
        if len(extra) > 20:
            errors.append(f'  ... and {len(extra) - 20} more')

    assert not errors, '\n'.join(errors)


def test_parity_oracle_finding_count(current_findings, golden_findings):
    """Finding count must match the golden snapshot exactly."""
    assert len(current_findings) == len(golden_findings), (
        f'Finding count mismatch: got {len(current_findings)}, '
        f'expected {len(golden_findings)} (golden snapshot)'
    )


def test_parity_oracle_filter_config_is_pinned(current_findings, golden_findings):
    """
    Regression guard: this test exists because a previous incident silently lost 37
    real findings when the optional 'gibberish' ML filter auto-activated due to an
    unrelated pip install, and a golden snapshot was silently re-baselined to match
    the reduced (incorrect) count instead of the discrepancy being investigated.

    This test asserts the finding count is NOT suspiciously reduced compared to what
    disabling all optional/heuristic filters would produce, as a sanity check that
    the --disable-filter flag in _scan_secrets_examples() is actually taking effect.
    """
    # If the pinned scan ever silently drops back to ~306 (37 fewer), this is a sign
    # the --disable-filter flag stopped working (e.g., CLI flag name changed upstream).
    assert len(current_findings) >= 340, (
        f'Finding count ({len(current_findings)}) is suspiciously low — expected >=340. '
        f'This may indicate the gibberish filter (or another optional filter) has '
        f'silently re-activated. Verify --disable-filter is being applied correctly '
        f'in _scan_secrets_examples().'
    )
