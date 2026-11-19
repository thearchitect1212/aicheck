"""Day 5: write the founder summary, engineer findings and coverage list."""

from __future__ import annotations

import html
import json
import os
from collections import Counter

from .probes import CATEGORY_TITLES
from .runner import SEVERITY_ORDER, findings

PLAIN = {
    "prompt_injection": "A user can talk the AI into ignoring its rules.",
    "indirect_injection": "Hidden text inside a document or web page can take control of the AI.",
    "policy_bypass": "The AI can be talked into breaking rules your business set for it.",
    "system_prompt_leak": "The AI reveals its hidden instructions, which can expose internal details.",
    "data_leak": "One customer can see another customer's information.",
    "excessive_agency": "The AI can be tricked into actions it should not take on its own.",
    "unsafe_output": "The AI's replies can carry code or links that your app may run or load.",
    "abuse_cost": "Someone can run up your AI bill or slow the service.",
}

SEV_COLORS = {"critical": "#b42318", "high": "#c4320a", "medium": "#b54708", "low": "#475467", "info": "#475467"}


def shorten(text: str, limit: int = 600) -> str:
    """Keep evidence readable: cut long replies and say how long they were."""
    text = text or ""
    if len(text) <= limit:
        return text
    return text[:limit].rstrip() + f" ... [cut off: the full reply was {len(text):,} characters]"


def overall_risk(fs: list[dict]) -> str:
    if not fs:
        return "Low"
    top = fs[0]["severity"]
    return {"critical": "Critical", "high": "High", "medium": "Medium"}.get(top, "Low")


def write_evidence(results: list[dict], out_dir: str) -> None:
    ev_dir = os.path.join(out_dir, "evidence")
    os.makedirs(ev_dir, exist_ok=True)
    for res in findings(results):
        pid = res["probe"]["id"]
        with open(os.path.join(ev_dir, f"{pid}.json"), "w", encoding="utf-8") as fh:
            json.dump(res, fh, indent=2)
        lines = [f"# Evidence: {pid} - {res['probe']['title']}", "",
                 f"Status: {res['status']} (reproduced {res.get('reproduced', '-')})", ""]
        runs = [("First run", res["exchanges"])] + [
            (f"Rerun {i}", r["exchanges"]) for i, r in enumerate(res.get("reruns", []), 1)]
        for label, exs in runs:
            lines.append(f"## {label}")
            for e in exs:
                lines += [f"**User {e['user']}** (HTTP {e['status']}, {e['latency']:.2f}s):", "",
                          "```", e["message"], "```"]
                if e.get("document"):
                    lines += ["Shared document:", "```", e["document"], "```"]
                lines += ["**Reply:**", "", "```", shorten(e["reply"], 3000), "```", ""]
        with open(os.path.join(ev_dir, f"{pid}.md"), "w", encoding="utf-8") as fh:
            fh.write("\n".join(lines))


def _steps(res: dict, md: bool = True) -> list[str]:
    out = []
    for s in res["probe"]["steps"]:
        who = f"**{s['user']}**" if md else s["user"]
        q = "`" if md else '"'
        line = f"As test user {who}"
        if s.get("fresh_session"):
            line += " (new conversation)"
        line += f", send: {q}{s['message'][:300]}{q}"
        if s.get("document"):
            line += f" with this document attached: {q}" + s["document"][:200].replace("\n", " ") + q
        out.append(line)
    if res["probe"]["check"]["type"] == "rate_limit":
        out.append(f"Repeat it {res['probe']['check']['burst']} times as fast as possible.")
    return [f"{i}. {l}" for i, l in enumerate(out, 1)] if md else out


def build_markdown(meta: dict, recon: dict, results: list[dict]) -> str:
    fs = findings(results)
    counts = Counter(f["severity"] for f in fs)
    L = [f"# AI Feature Security Check: {meta['client']}", "",
         f"Feature tested: {meta['feature_name']}  ",
         f"Test dates: {meta['started'][:10]}  ",
         f"Tester: {meta['tester']}  ", f"Run ID: {meta['run_id']}", "",
         "## Summary for the founder", "",
         f"**Overall risk: {overall_risk(fs)}.** We ran {meta['probes_run']} tests across "
         f"{len({r['probe']['category'] for r in results if r['verdict'] != 'skipped'})} risk areas and found "
         f"{len(fs)} issue(s): " + ", ".join(f"{counts[s]} {s}" for s in SEVERITY_ORDER if counts[s]) + "." if fs
         else f"**Overall risk: Low.** We ran {meta['probes_run']} tests and found no issues.", ""]
    if fs:
        L.append("What this means for your business:")
        L.append("")
        seen = []
        for f in fs:
            cat = f["probe"]["category"]
            if cat not in seen:
                seen.append(cat)
                L.append(f"- **{f['severity'].title()}:** {PLAIN[cat]}")
        L += ["", "Next step: fix the critical and high issues first, then book the free retest to confirm they are closed.", ""]

    L += ["## What the AI can see and do", ""]
    d = recon["declared"]
    L += [f"- Sees: {', '.join(d['sees']) or 'not stated'}",
          f"- Can do: {', '.join(d['can_do']) or 'not stated'}",
          f"- Used by: {d['users'] or 'not stated'}",
          f"- Must never: {', '.join(d['must_never']) or 'not stated'}",
          f"- Capabilities the AI described itself: {', '.join(recon['detected_capabilities']) or 'none'}", ""]

    L += ["## Findings for engineers", ""]
    if not fs:
        L += ["No issues found.", ""]
    for n, f in enumerate(fs, 1):
        p = f["probe"]
        L += [f"### {n}. [{f['severity'].upper()}] {CATEGORY_TITLES[p['category']]}: {p['title']}", "",
              f"- OWASP: {p['owasp']}", f"- Status: {f['status']} (reproduced {f.get('reproduced', '-')} reruns)",
              f"- Test ID: `{p['id']}`", "", f"**What happened:** {f['detail']}", "",
              "**Steps to reproduce:**", "", *_steps(f), "",
              "**Evidence:** reply excerpt", "", "```", shorten(f["exchanges"][-1]["reply"] if f["exchanges"] else ""), "```", "",
              f"Full transcript: `evidence/{p['id']}.md`", "", f"**How to fix:** {f['fix']}", ""]

    L += ["## What we tested", "", "| Test ID | Area | Test | Result |", "| --- | --- | --- | --- |"]
    for r in results:
        p = r["probe"]
        result = r.get("status") or r["verdict"]
        if r["verdict"] == "skipped":
            result = f"skipped: {r['detail']}"
        L.append(f"| {p['id']} | {CATEGORY_TITLES[p['category']]} | {p['title'][:60]} | {result} |")
    L += ["", "## Limits of this test", "",
          "- Tests ran only against the scope in the signed permission letter, during the agreed dates.",
          "- Automated tests miss issues specific to your business logic; manual testing covered the items listed above.",
          "- AI replies vary between runs, so a passed test is not a guarantee. Retest after every major prompt or model change.",
          "- This is not a certification or audit opinion.", ""]
    return "\n".join(L)


def build_html(meta: dict, recon: dict, results: list[dict]) -> str:
    fs = findings(results)
    counts = Counter(f["severity"] for f in fs)
    e = html.escape

    def badge(sev):
        return f'<span class="b" style="background:{SEV_COLORS.get(sev, "#475467")}">{e(sev.upper())}</span>'

    tiles = "".join(f'<div class="t"><div class="n">{counts[s]}</div><div>{s.title()}</div></div>'
                    for s in ["critical", "high", "medium", "low"])
    meaning = ""
    seen = []
    for f in fs:
        cat = f["probe"]["category"]
        if cat not in seen:
            seen.append(cat)
            meaning += f"<li>{badge(f['severity'])} {e(PLAIN[cat])}</li>"

    finding_html = ""
    for n, f in enumerate(fs, 1):
        p = f["probe"]
        steps = "".join(f"<li>{e(s)}</li>" for s in _steps(f, md=False))
        reply = e(shorten(f["exchanges"][-1]["reply"] if f["exchanges"] else ""))
        finding_html += f"""
<section class="f"><h3>{n}. {badge(f['severity'])} {e(CATEGORY_TITLES[p['category']])}: {e(p['title'])}</h3>
<p class="m">{e(p['owasp'])} &middot; Status: {e(f['status'])} (reproduced {e(f.get('reproduced', '-'))}) &middot; Test ID <code>{e(p['id'])}</code></p>
<p><b>What happened:</b> {e(f['detail'])}</p>
<p><b>Steps to reproduce:</b></p><ol>{steps}</ol>
<p><b>Evidence (reply excerpt):</b></p><pre>{reply}</pre>
<p class="m">Full transcript: evidence/{e(p['id'])}.md</p>
<p><b>How to fix:</b> {e(f['fix'])}</p></section>"""

    rows = ""
    for r in results:
        p = r["probe"]
        result = r.get("status") or r["verdict"]
        if r["verdict"] == "skipped":
            result = "skipped: " + r["detail"]
        rows += f"<tr><td><code>{e(p['id'])}</code></td><td>{e(CATEGORY_TITLES[p['category']])}</td><td>{e(p['title'][:70])}</td><td>{e(result)}</td></tr>"

    d = recon["declared"]
    return f"""<!DOCTYPE html><html><head><meta charset="utf-8"><title>AI Feature Security Check - {e(meta['client'])}</title>
<style>body{{font:15px/1.55 -apple-system,Segoe UI,Roboto,sans-serif;color:#101828;max-width:900px;margin:40px auto;padding:0 20px}}
h1{{font-size:26px;margin-bottom:4px}}h2{{margin-top:36px;border-bottom:1px solid #eaecf0;padding-bottom:6px}}
.m{{color:#475467;font-size:13px}}.b{{color:#fff;border-radius:4px;padding:1px 7px;font-size:11px;font-weight:700;letter-spacing:.03em}}
.tiles{{display:flex;gap:12px;margin:16px 0}}.t{{flex:1;border:1px solid #eaecf0;border-radius:8px;padding:12px;text-align:center}}
.n{{font-size:28px;font-weight:700}}.risk{{font-size:20px;font-weight:700}}
.f{{border:1px solid #eaecf0;border-radius:8px;padding:4px 18px;margin:16px 0}}
pre{{background:#f9fafb;border:1px solid #eaecf0;padding:10px;white-space:pre-wrap;word-break:break-word;font-size:12.5px}}
table{{border-collapse:collapse;width:100%;font-size:13px}}td,th{{border-bottom:1px solid #eaecf0;padding:6px;text-align:left;vertical-align:top}}
ul li{{margin:4px 0}}</style></head><body>
<h1>AI Feature Security Check: {e(meta['client'])}</h1>
<p class="m">Feature: {e(meta['feature_name'])} &middot; Tested {e(meta['started'][:10])} &middot; Tester: {e(meta['tester'])} &middot; Run {e(meta['run_id'])}</p>
<h2>Summary for the founder</h2>
<p class="risk">Overall risk: {overall_risk(fs)}</p>
<p>We ran {meta['probes_run']} tests and found {len(fs)} issue(s).</p>
<div class="tiles">{tiles}</div>
{"<p><b>What this means for your business:</b></p><ul>" + meaning + "</ul><p>Next step: fix the critical and high issues first, then book the free retest to confirm they are closed.</p>" if fs else "<p>No issues found.</p>"}
<h2>What the AI can see and do</h2><ul>
<li>Sees: {e(', '.join(d['sees']) or 'not stated')}</li><li>Can do: {e(', '.join(d['can_do']) or 'not stated')}</li>
<li>Used by: {e(d['users'] or 'not stated')}</li><li>Must never: {e(', '.join(d['must_never']) or 'not stated')}</li>
<li>Capabilities the AI described itself: {e(', '.join(recon['detected_capabilities']) or 'none')}</li></ul>
<h2>Findings for engineers</h2>{finding_html or '<p>No issues found.</p>'}
<h2>What we tested</h2><table><tr><th>Test ID</th><th>Area</th><th>Test</th><th>Result</th></tr>{rows}</table>
<h2>Limits of this test</h2><ul>
<li>Tests ran only against the scope in the signed permission letter, during the agreed dates.</li>
<li>Automated tests miss issues specific to your business logic.</li>
<li>AI replies vary between runs, so a passed test is not a guarantee. Retest after every major prompt or model change.</li>
<li>This is not a certification or audit opinion.</li></ul></body></html>"""


def write_reports(meta: dict, recon: dict, results: list[dict], out_dir: str) -> dict:
    write_evidence(results, out_dir)
    md = os.path.join(out_dir, "report.md")
    ht = os.path.join(out_dir, "report.html")
    with open(md, "w", encoding="utf-8") as fh:
        fh.write(build_markdown(meta, recon, results))
    with open(ht, "w", encoding="utf-8") as fh:
        fh.write(build_html(meta, recon, results))
    return {"markdown": md, "html": ht}


def build_retest_markdown(meta: dict, rows: list[dict]) -> str:
    fixed = sum(1 for r in rows if r["now"] == "fixed")
    L = [f"# Retest: {meta['client']}", "", f"Original run: {meta['run_id']}  ", f"Retest date: {meta['retest_date']}", "",
         f"**{fixed} of {len(rows)} issues are fixed.**", "",
         "| Test ID | Severity | Issue | Before | Now |", "| --- | --- | --- | --- | --- |"]
    for r in rows:
        L.append(f"| {r['id']} | {r['severity']} | {r['title'][:60]} | {r['before']} | {r['now']} ({r['reproduced']}) |")
    L += ["", "A test counts as fixed only when none of the reruns reproduce it and the target answered every rerun. 'could not test' means the target returned errors, so check it by hand."]
    return "\n".join(L)


def build_retest_html(meta: dict, rows: list[dict]) -> str:
    e = html.escape
    fixed = sum(1 for r in rows if r["now"] == "fixed")
    body = ""
    for r in rows:
        color = {"fixed": "#067647", "still open": "#b42318"}.get(r["now"], "#b54708")
        body += (f"<tr><td><code>{e(r['id'])}</code></td>"
                 f"<td><span class='b' style='background:{SEV_COLORS.get(r['severity'], '#475467')}'>{e(r['severity'].upper())}</span></td>"
                 f"<td>{e(r['title'])}</td><td>{e(r['before'])}</td>"
                 f"<td style='color:{color};font-weight:700'>{e(r['now'])}</td><td>{e(r['reproduced'])}</td></tr>")
    return f"""<!DOCTYPE html><html><head><meta charset="utf-8"><title>Retest - {e(meta['client'])}</title>
<style>body{{font:15px/1.55 -apple-system,Segoe UI,Roboto,sans-serif;color:#101828;max-width:900px;margin:40px auto;padding:0 20px}}
.m{{color:#475467;font-size:13px}}.b{{color:#fff;border-radius:4px;padding:1px 7px;font-size:11px;font-weight:700}}
.big{{font-size:22px;font-weight:700;margin:18px 0}}table{{border-collapse:collapse;width:100%;font-size:13px}}
td,th{{border-bottom:1px solid #eaecf0;padding:7px;text-align:left;vertical-align:top}}td:nth-child(5),td:nth-child(2){{white-space:nowrap}}</style></head><body>
<h1>Retest: {e(meta['client'])}</h1>
<p class="m">Original run {e(meta['run_id'])} &middot; Retest date {e(meta['retest_date'])}</p>
<p class="big">{fixed} of {len(rows)} issues are fixed.</p>
<table><tr><th>Test ID</th><th>Severity</th><th>Issue</th><th>Before</th><th>Now</th><th>Reproduced</th></tr>{body}</table>
<p class="m">A test counts as fixed only when none of the reruns reproduce it and the target answered every rerun.</p></body></html>"""
