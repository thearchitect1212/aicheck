"""Export confirmed findings to promptfoo (for retests and client CI) and a garak setup."""

from __future__ import annotations

import json
import os

import yaml

from .runner import findings


def export_promptfoo(cfg: dict, results: list[dict], out_dir: str) -> str:
    t = cfg["target"]
    body = json.loads(json.dumps(t.get("body_template", {"message": "{{message}}"}))
                      .replace("{{message}}", "{{prompt}}"))
    provider = {
        "id": "https",
        "config": {
            "url": t["url"], "method": t.get("method", "POST"),
            "headers": t.get("headers", {}), "body": body,
            "transformResponse": "json." + t.get("response_path", "reply"),
        },
    }
    tests = []
    for f in findings(results):
        p = f["probe"]
        steps = [s for s in p["steps"] if not s.get("document")]
        if len(steps) != 1 or p["check"]["type"] not in ("contains", "raw_html", "external_image", "any_contains"):
            continue
        check = p["check"]
        values = check.get("values") or [check["value"]]
        tests.append({
            "description": f"{p['id']} {p['title']}",
            "vars": {"prompt": steps[0]["message"]},
            "assert": [{"type": "not-icontains", "value": v} for v in values],
        })
    doc = {"description": f"aicheck regression tests for {cfg['authorization']['client']}",
           "prompts": ["{{prompt}}"], "providers": [provider], "tests": tests}
    path = os.path.join(out_dir, "promptfooconfig.yaml")
    with open(path, "w", encoding="utf-8") as fh:
        yaml.safe_dump(doc, fh, sort_keys=False)
    return path


def export_garak(cfg: dict, out_dir: str) -> str:
    t = cfg["target"]
    body = json.loads(json.dumps(t.get("body_template", {"message": "{{message}}"}))
                      .replace("{{message}}", "$INPUT"))
    gen = {"rest": {"RestGenerator": {
        "name": "aicheck-target", "uri": t["url"], "method": t.get("method", "POST").lower(),
        "headers": t.get("headers", {}), "req_template_json_object": body,
        "response_json": True, "response_json_field": t.get("response_path", "reply"),
    }}}
    path = os.path.join(out_dir, "garak_rest.json")
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(gen, fh, indent=2)
    with open(os.path.join(out_dir, "run_garak.sh"), "w", encoding="utf-8") as fh:
        fh.write("#!/bin/sh\n# Extra automated sweep with garak (pip install garak). Only within the authorized scope.\n"
                 f"python -m garak --model_type rest -G {os.path.basename(path)} "
                 "--probes promptinject,dan,leakreplay,encoding,xss\n")
    return path
