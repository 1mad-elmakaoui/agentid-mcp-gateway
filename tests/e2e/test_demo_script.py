"""The demo script is part of the deliverable, so it is tested like one."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

pytestmark = pytest.mark.e2e

ROOT = Path(__file__).resolve().parents[2]


def _run(*args: str) -> subprocess.CompletedProcess[str]:
    # A subprocess keeps the demo's global engine configuration out of the
    # test session's own.
    return subprocess.run(
        [sys.executable, str(ROOT / "scripts" / "demo.py"), *args],
        capture_output=True,
        text=True,
        cwd=ROOT,
        timeout=180,
    )


def test_demo_runs_and_reports_success() -> None:
    result = _run()
    assert result.returncode == 0, result.stderr
    assert "1. ALLOWED" in result.stdout
    assert "2. DENIED" in result.stdout
    assert "4. AUTONOMOUS AGENT" in result.stdout
    assert "5. AUDIT TRAIL" in result.stdout


def test_demo_json_output_matches_the_documented_outcomes() -> None:
    result = _run("--json")
    assert result.returncode == 0, result.stderr
    scenarios = {entry["scenario"]: entry for entry in json.loads(result.stdout)}

    assert scenarios["allowed"]["status"] == 200
    assert scenarios["denied"]["status"] == 403
    assert scenarios["service_account"]["status"] == 403
    assert scenarios["autonomous"]["status"] == 200

    autonomous = scenarios["autonomous"]["body"]
    assert autonomous["execution_identity"].startswith("sa_")

    events = scenarios["audit"]["events"]
    assert len(events) >= 4
    assert {e["decision"] for e in events} == {"allow", "deny"}
    # The autonomous event carries no human identity.
    assert any(e["user_id"] is None and e["persona"] == "non-user" for e in events)
    # No secret material anywhere in the trail.
    assert "downstream-github-secret" not in json.dumps(events)
