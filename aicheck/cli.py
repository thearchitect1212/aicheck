"""Command line: run the full check, retest, or export."""

from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import sys
import uuid

from . import __version__
from .config import AuthorizationError, check_authorization, load_config
from .export import export_garak, export_promptfoo
from .probes import build_probes
from .recon import run_recon
from .report import build_retest_html, build_retest_markdown, write_reports
from .runner import confirm, execute, findings, rank, run_probes
from .target import Target


def _gate(cfg):
    try:
        auth = check_authorization(cfg)
    except AuthorizationError as exc:
        sys.exit(f"STOPPED: not authorized. {exc}")
    print(f"Authorized: {auth['client']}, signed by {auth['signed_by']}, window {auth['window']}")
    return auth


def cmd_run(args):
    cfg = load_config(args.config)
    auth = _gate(cfg)
    run_id = dt.datetime.now().strftime("%Y%m%d") + "-" + uuid.uuid4().hex[:4]
    out = args.out or os.path.join("runs", run_id)
    os.makedirs(out, exist_ok=True)
    target = Target(cfg)
    started = dt.datetime.now().isoformat(timespec="seconds")

    print("\nDay 1: mapping the feature")
    recon = run_recon(target, cfg)
    print(f"  detected capabilities: {', '.join(recon['detected_capabilities']) or 'none'}")
    print(f"  documents: {recon['supports_documents']}  two users: {recon['multi_user']}  action log: {recon['action_log']}")

    print("\nDays 2-3: testing against the OWASP LLM Top 10")
    probes = build_probes(cfg, recon, run_id)
    results = run_probes(probes, target, cfg)

    print("\nDay 4: confirming and ranking")
    results = rank(confirm(results, target, cfg))

    meta = {"client": auth["client"], "feature_name": cfg.get("feature", {}).get("name", "AI feature"),
            "tester": cfg.get("tester", ""), "run_id": run_id, "started": started,
            "finished": dt.datetime.now().isoformat(timespec="seconds"),
            "probes_run": sum(1 for r in results if r["verdict"] != "skipped"),
            "requests_sent": target.request_count, "authorization": auth, "tool_version": __version__}
    with open(os.path.join(out, "results.json"), "w", encoding="utf-8") as fh:
        json.dump({"meta": meta, "recon": recon, "results": results}, fh, indent=2)

    print("\nDay 5: writing the report")
    paths = write_reports(meta, recon, results, out)
    export_promptfoo(cfg, results, out)
    export_garak(cfg, out)

    fs = findings(results)
    print(f"\nDone. {len(fs)} finding(s) from {meta['probes_run']} tests, {target.request_count} requests.")
    for f in fs:
        print(f"  [{f['severity'].upper():<8}] {f['probe']['id']:<22} {f['probe']['title'][:50]} ({f['status']})")
    print(f"\nReport: {paths['html']}\nResults: {os.path.join(out, 'results.json')}")


def cmd_retest(args):
    cfg = load_config(args.config)
    _gate(cfg)
    with open(args.results, encoding="utf-8") as fh:
        prev = json.load(fh)
    target = Target(cfg)
    rows = []
    print("Retesting previous findings")
    for f in findings(prev["results"]):
        runs = [execute(f["probe"], target, cfg) for _ in range(max(2, int(cfg.get("confirm_runs", 2))))]
        hits = sum(1 for r in runs if r["verdict"] in ("vulnerable", "possible"))
        errors = sum(1 for r in runs if r["verdict"] == "error")
        if hits:
            now = "still open"
        elif errors:
            now = "could not test"
        else:
            now = "fixed"
        rows.append({"id": f["probe"]["id"], "severity": f["severity"], "title": f["probe"]["title"],
                     "before": f["status"], "now": now, "reproduced": f"{hits}/{len(runs)}"})
        print(f"  {f['probe']['id']:<22} {now} ({hits}/{len(runs)})")
    meta = {"client": prev["meta"]["client"], "run_id": prev["meta"]["run_id"],
            "retest_date": dt.date.today().isoformat()}
    folder = os.path.dirname(os.path.abspath(args.results))
    with open(os.path.join(folder, "retest.md"), "w", encoding="utf-8") as fh:
        fh.write(build_retest_markdown(meta, rows))
    out = os.path.join(folder, "retest.html")
    with open(out, "w", encoding="utf-8") as fh:
        fh.write(build_retest_html(meta, rows))
    print(f"\nRetest report: {out}")


def cmd_check_auth(args):
    cfg = load_config(args.config)
    auth = _gate(cfg)
    print(json.dumps(auth, indent=2))


def main(argv=None):
    ap = argparse.ArgumentParser(prog="aicheck", description="Automated security check for AI features.")
    ap.add_argument("--version", action="version", version=__version__)
    sub = ap.add_subparsers(dest="cmd", required=True)

    r = sub.add_parser("run", help="run the full check (days 1-5)")
    r.add_argument("--config", required=True)
    r.add_argument("--out")
    r.set_defaults(func=cmd_run)

    rt = sub.add_parser("retest", help="rerun previous findings and say which are fixed")
    rt.add_argument("--config", required=True)
    rt.add_argument("--results", required=True)
    rt.set_defaults(func=cmd_retest)

    ca = sub.add_parser("check-auth", help="only check the permission letter and scope")
    ca.add_argument("--config", required=True)
    ca.set_defaults(func=cmd_check_auth)

    args = ap.parse_args(argv)
    args.func(args)


if __name__ == "__main__":
    main()
