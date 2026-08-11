"""
Parity oracle: scans secrets-examples/ and asserts findings match the golden snapshot.

This test MUST pass before and after every optimization. Any difference in findings
indicates a regression — the optimization must be reverted.

Run with:
    pytest tests/perf/parity_oracle_test.py -v
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).parent.parent.parent  # detect-secrets/
# Vendored fixture copy of the secrets-examples corpus (committed to this repo so the
# parity oracle is self-contained and works identically in CI, which only checks out
# this repository and has no access to any sibling directory).
FIXTURES_DIR = REPO_ROOT / 'tests' / 'perf' / 'fixtures'
SECRETS_EXAMPLES = FIXTURES_DIR / 'secrets-examples'
GOLDEN_SNAPSHOT = REPO_ROOT / 'baselines' / 'parity_snapshot.json'

# One golden-snapshot finding (secrets-examples/.git/config:9, a GitHub Token) lives
# inside a nested .git/ directory. Git refuses to track any path containing a literal
# ".git" path component (it looks like a submodule/gitlink), so that fixture's content
# is stored under this plain filename instead and materialized into a real
# secrets-examples/.git/config at test time (see _ensure_git_config_fixture()).
# The token inside is a deliberately fake, non-functional placeholder value —
# it only needs to match the GitHubTokenDetector's regex shape.
_GIT_CONFIG_FIXTURE_SRC = FIXTURES_DIR / 'secrets-examples-git-config-fixture.txt'
_GIT_CONFIG_FIXTURE_DEST = SECRETS_EXAMPLES / '.git' / 'config'


def _ensure_git_config_fixture() -> None:
    """Materialize secrets-examples/.git/config from its git-trackable source file.

    Idempotent: safe to call every test run, including in parallel/repeat invocations.
    """
    _GIT_CONFIG_FIXTURE_DEST.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(_GIT_CONFIG_FIXTURE_SRC, _GIT_CONFIG_FIXTURE_DEST)

# Prefer the local perf-benchmarking venv's console script when present (developer
# machines only — see scripts/perf_benchmark.py). CI never creates .venv-perf, so we
# fall back to invoking the detect_secrets package with the current interpreter
# (`python -m detect_secrets`), which works with whatever environment `pytest` is
# already running under (e.g. the one built from requirements-dev.txt in CI).
_VENV_PERF_BIN = REPO_ROOT / '.venv-perf' / 'bin' / 'detect-secrets'
if _VENV_PERF_BIN.exists():
    _DETECT_SECRETS_CMD = [str(_VENV_PERF_BIN)]
else:
    _DETECT_SECRETS_CMD = [sys.executable, '-m', 'detect_secrets']


def _scan_secrets_examples() -> list[dict]:
    """Run detect-secrets scan on secrets-examples/ and return normalized findings.

    IMPORTANT: The subprocess must run with cwd=FIXTURES_DIR because detect-secrets
    uses the CWD to resolve git boundaries, and secrets-examples/ contains its own
    nested .git/ (materialized on the fly by _ensure_git_config_fixture() from a
    sanitized, non-functional stand-in — see secrets-examples-git-config-fixture.txt
    — used only to exercise the GitHub Token detector). Running from detect-secrets/
    itself would make the tool resolve paths relative to *this* repo's git boundary
    instead of treating secrets-examples/ as its own scan root, which changes the
    reported file paths and breaks parity with the golden snapshot (paths are stored
    as "secrets-examples/...").
    Output format (standard detect-secrets):
        {"results": {"filename": [{"line_number": ..., "type": ...}, ...]}}
    """
    _ensure_git_config_fixture()

    # Run from tests/perf/fixtures/ so detect-secrets reports paths as "secrets-examples/..."
    # matching the golden snapshot, and resolves the nested fixture .git/ boundary correctly.
    cwd = FIXTURES_DIR

    # When falling back to `python -m detect_secrets` (no .venv-perf console script),
    # the subprocess's cwd is FIXTURES_DIR (see above), which does not have the
    # detect_secrets package importable by default. Prepend REPO_ROOT to PYTHONPATH
    # so `-m detect_secrets` resolves regardless of cwd or how pytest itself was
    # installed/invoked (editable install, sys.path insert, etc.).
    env = dict(os.environ)
    env['PYTHONPATH'] = os.pathsep.join(
        filter(None, [str(REPO_ROOT), env.get('PYTHONPATH', '')]),
    )

    result = subprocess.run(
        [
            *_DETECT_SECRETS_CMD,
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
        env=env,
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
