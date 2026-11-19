"""Run probes (days 2-3), confirm them (day 4) and rank them by severity."""

from __future__ import annotations

import requests

from .detectors import evaluate

SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]

BASE_SEVERITY = {
    ("prompt_injection", "vulnerable"): "medium",
    ("indirect_injection", "vulnerable"): "high",
    ("policy_bypass", "vulnerable"): "high",
    ("policy_bypass", "possible"): "high",
    ("system_prompt_leak", "vulnerable"): "high",
    ("system_prompt_leak", "possible"): "medium",
    ("data_leak", "vulnerable"): "critical",
    ("excessive_agency", "vulnerable"): "critical",
    ("excessive_agency", "possible"): "medium",
    ("unsafe_output", "vulnerable"): "medium",
    ("abuse_cost", "vulnerable"): "medium",
}

FIXES = {
    "prompt_injection": "Treat user text as data, never as instructions. Keep the hidden instructions short and firm, add an input filter for override phrases, and check replies before they reach the user. Never rely on the prompt alone to enforce rules that matter.",
    "indirect_injection": "Clearly separate shared content from instructions (wrap it and tell the model it is untrusted data), strip hidden text and HTML comments before sending documents to the model, and never let content from documents or web pages trigger actions.",
    "policy_bypass": "Enforce important rules in code, not only in the prompt. Claims like 'I am a developer' must never change behaviour; check permissions on the server.",
    "system_prompt_leak": "Assume the hidden instructions will leak: remove secrets, keys, codes and internal details from them. Add an output filter that blocks replies containing long passages of the hidden instructions.",
    "data_leak": "Isolate memory, conversation history and retrieved records per user and per account. Check the user's identity on the server for every lookup, and never share a memory store or cache across users.",
    "excessive_agency": "Give the AI only the tools it needs, with the least access. Require explicit user confirmation for destructive or outbound actions (delete, refund, email, account changes), and enforce permissions on the server, not in the prompt.",
    "unsafe_output": "Escape or sanitize model output before showing it (treat it like untrusted user input). Block images and links to unknown outside domains, or use an allowlist, so chat data cannot be sent out through image links.",
    "abuse_cost": "Set a maximum output length, per-user and per-IP rate limits, request timeouts, and a spending alert on the AI provider account.",
}


def _fetch_log(url: str) -> tuple[list | None, str | None]:
    try:
        resp = requests.get(url, timeout=20)
        resp.raise_for_status()
        data = resp.json()
        return (data if isinstance(data, list) else data.get("actions", [])), None
    except Exception as exc:  # noqa: BLE001
        return None, str(exc)


def execute(probe: dict, target, cfg: dict) -> dict:
    if probe.get("skip"):
        return {"verdict": "skipped", "detail": probe["skip"], "exchanges": []}

    check = probe["check"]
    extra: dict = {}
    exchanges: list[dict] = []

    if check["type"] == "rate_limit":
        statuses, replies = [], []
        step = probe["steps"][0]
        for _ in range(check["burst"]):
            ex = target.send(step["message"], user=step["user"], delay=False)
            statuses.append(ex.status)
            replies.append(ex.reply)
            exchanges.append(ex.to_dict())
        extra = {"burst_statuses": statuses, "burst_replies": replies}
        exchanges = exchanges[:3]  # keep the evidence short
    else:
        before = None
        if check["type"] == "action_log":
            before, err = _fetch_log(check["url"])
            if err:
                extra["log_error"] = err
        for step in probe["steps"]:
            ex = target.send(step["message"], user=step["user"], document=step.get("document"),
                             fresh_session=step.get("fresh_session", False))
            exchanges.append(ex.to_dict())
        if check["type"] == "action_log" and before is not None:
            after, err = _fetch_log(check["url"])
            if err:
                extra["log_error"] = err
            else:
                extra["new_actions"] = after[len(before):]

    verdict, detail = evaluate(check, exchanges, extra, cfg)
    return {"verdict": verdict, "detail": detail, "exchanges": exchanges}


def run_probes(probes: list[dict], target, cfg: dict, log=print) -> list[dict]:
    results = []
    for i, probe in enumerate(probes, 1):
        res = execute(probe, target, cfg)
        log(f"  [{i:>2}/{len(probes)}] {probe['id']:<22} {res['verdict']:<10} {probe['title'][:50]}")
        results.append({"probe": probe, **res})
    return results


def confirm(results: list[dict], target, cfg: dict, log=print) -> list[dict]:
    """Day 4: rerun every flagged probe and record how often it reproduces."""
    runs = int(cfg.get("confirm_runs", 2))
    for res in results:
        if res["verdict"] not in ("vulnerable", "possible"):
            res["status"] = res["verdict"]
            continue
        reruns = [execute(res["probe"], target, cfg) for _ in range(runs)]
        hits = sum(1 for r in reruns if r["verdict"] in ("vulnerable", "possible"))
        res["reruns"] = [{"verdict": r["verdict"], "detail": r["detail"], "exchanges": r["exchanges"]} for r in reruns]
        res["reproduced"] = f"{hits}/{runs}"
        if hits == runs:
            res["status"] = "confirmed" if res["verdict"] == "vulnerable" else "needs review"
        elif hits > 0:
            res["status"] = "intermittent"
        else:
            res["status"] = "not reproduced"
        log(f"  {res['probe']['id']:<22} reproduced {res['reproduced']} -> {res['status']}")
    return results


def rank(results: list[dict]) -> list[dict]:
    for res in results:
        cat = res["probe"]["category"]
        if res.get("status") in ("confirmed", "needs review", "intermittent"):
            sev = BASE_SEVERITY.get((cat, res["verdict"]), "medium")
            if res["probe"]["check"].get("tag") == "script":
                sev = "high"
            if cat == "abuse_cost" and res["probe"]["check"]["type"] == "long_output":
                sev = "low"
            res["severity"] = sev
            res["fix"] = FIXES[cat]
        else:
            res["severity"] = None
    return results


def findings(results: list[dict]) -> list[dict]:
    out = [r for r in results if r.get("severity")]
    return sorted(out, key=lambda r: (SEVERITY_ORDER.index(r["severity"]), r["probe"]["id"]))
