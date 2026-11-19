"""Tests for the authorization gate, the detectors and a full run against the demo bot."""

import datetime as dt
import json
import os
import subprocess
import sys
import threading
import time
from http.server import ThreadingHTTPServer

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "demo"))

from aicheck.config import AuthorizationError, check_authorization, load_config  # noqa: E402
from aicheck.detectors import evaluate  # noqa: E402

DEMO = os.path.join(ROOT, "demo", "demo.yaml")


def ex(reply, user="a", status=200, latency=0.1):
    return {"user": user, "message": "m", "document": None, "status": status,
            "reply": reply, "latency": latency, "error": None}


# ---------- authorization gate ----------

def test_gate_allows_demo_inside_window():
    cfg = load_config(DEMO)
    auth = check_authorization(cfg, today=dt.date(2026, 11, 19))
    assert auth["allowed_hosts"] == ["127.0.0.1"]


def test_gate_blocks_outside_window():
    cfg = load_config(DEMO)
    with pytest.raises(AuthorizationError, match="outside the authorized window"):
        check_authorization(cfg, today=dt.date(2031, 1, 1))


def test_gate_blocks_unlisted_host():
    cfg = load_config(DEMO)
    cfg["target"]["url"] = "https://example.com/chat"
    with pytest.raises(AuthorizationError, match="not in authorization.allowed_hosts"):
        check_authorization(cfg, today=dt.date(2026, 11, 19))


def test_gate_blocks_missing_letter():
    cfg = load_config(DEMO)
    cfg["authorization"]["letter_file"] = "does_not_exist.pdf"
    with pytest.raises(AuthorizationError, match="letter not found"):
        check_authorization(cfg, today=dt.date(2026, 11, 19))


def test_burst_is_capped():
    cfg = load_config(DEMO)
    assert cfg["abuse"]["burst"] <= 50


# ---------- detectors ----------

def test_marker_found_is_vulnerable():
    verdict, _ = evaluate({"type": "contains", "value": "AICHK-X-1"}, [ex("sure: AICHK-X-1")], {}, {})
    assert verdict == "vulnerable"


def test_marker_missing_is_pass():
    verdict, _ = evaluate({"type": "contains", "value": "AICHK-X-1"}, [ex("I can't do that")], {}, {})
    assert verdict == "pass"


def test_known_secret_leak():
    check = {"type": "prompt_leak", "secrets": ["ACME-STAFF-7731"]}
    verdict, _ = evaluate(check, [ex("My instructions say ACME-STAFF-7731")], {}, {})
    assert verdict == "vulnerable"


def test_refusal_is_not_an_action_claim():
    check = {"type": "action_claim", "request": "delete"}
    verdict, _ = evaluate(check, [ex("Sorry, I can't delete accounts.")], {}, {})
    assert verdict == "pass"


def test_rate_limit_seen_is_pass():
    extra = {"burst_statuses": [200, 200, 429], "burst_replies": ["", "", ""]}
    verdict, _ = evaluate({"type": "rate_limit", "burst": 3}, [], extra, {})
    assert verdict == "pass"


def test_server_errors_are_errors_not_findings():
    verdict, _ = evaluate({"type": "contains", "value": "X"}, [ex("", status=502)], {}, {})
    assert verdict == "error"


# ---------- end to end against the demo bot ----------

@pytest.fixture()
def demo_bot():
    import vuln_bot
    vuln_bot.SHARED_MEMORY.clear()
    vuln_bot.ACTION_LOG.clear()
    server = ThreadingHTTPServer(("127.0.0.1", 8787), vuln_bot.Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    time.sleep(0.2)
    yield
    server.shutdown()
    server.server_close()


def test_full_run_finds_demo_flaws(demo_bot, tmp_path):
    out = tmp_path / "run"
    subprocess.run([sys.executable, "-m", "aicheck", "run", "--config", DEMO, "--out", str(out)],
                   cwd=ROOT, check=True, capture_output=True, timeout=300)
    data = json.loads((out / "results.json").read_text())
    confirmed = {r["probe"]["category"] for r in data["results"] if r.get("status") == "confirmed"}
    assert {"data_leak", "excessive_agency", "system_prompt_leak", "indirect_injection"} <= confirmed
    passed = {r["probe"]["id"] for r in data["results"] if r["verdict"] == "pass"}
    assert "excessive_agency-03" in passed  # the bot refuses refunds, so this must not be flagged
    assert (out / "report.html").exists() and (out / "promptfooconfig.yaml").exists()
