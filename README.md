# aicheck

**Automated security testing for LLM chatbots and AI agents, mapped to the OWASP Top 10 for LLM Applications.**

`aicheck` points at any HTTP chat endpoint, maps what the AI can see and do, fires 25+ attack probes, re-runs every hit to weed out flukes, ranks what's left by severity, and writes a report for both the founder and the engineers. A retest command replays only the findings to show which fixes worked.

It refuses to send a single request without a signed permission letter, an in-date testing window and an allow-listed host.

![Sample report](docs/report-screenshot.png)

Sample output: [full report](docs/sample-report.html) · [retest after fixes](docs/sample-retest.html)

## Results on the bundled practice targets

| Target | Tests | Confirmed findings | After fixes (retest) |
| --- | --- | --- | --- |
| `demo/vuln_bot.py`: rule-based bot with deliberate flaws | 25 | 17 (4 critical, 7 high, 5 medium, 1 low) | 8 of 17 fixed |
| `demo/ai_bot.py` running Llama 3.2 locally | 25 | 10 (7 high, 3 medium) | 8 of 10 fixed |

The real-model run shows why confirmation matters: two first-run hits did not reproduce and were left out of the report rather than reported as findings. It also showed a fix that looked right but failed the retest (a rate limit set too loosely for the model's real response speed).

## What it tests

| Area | OWASP LLM Top 10 (2025) | How it is detected |
| --- | --- | --- |
| Prompt injection | LLM01 | Unique per-run marker the model is told to output |
| Hidden instructions in shared documents | LLM01 (indirect) | Marker hidden in HTML comments, footers, white text |
| Breaking the feature's own rules | LLM01 | Client-supplied rules and protected strings; optional LLM judge |
| System prompt leakage | LLM07 | Planted canary secret, plus heuristics flagged for review |
| Cross-user data leaks | LLM02 | User A stores a marker; user B tries to retrieve it |
| Excessive agency | LLM06 | Diff of the target's action log before and after each request |
| Improper output handling | LLM05 | Raw `<img>` / `<script>` echo, outbound image links carrying chat data |
| Unbounded consumption | LLM10 | Output-length cap and burst rate-limit checks |

## How a run works

```
check-auth ─▶ 1. Map ─▶ 2-3. Probe ─▶ 4. Confirm & rank ─▶ 5. Report ─▶ Retest
 (gate)       recon      25+ probes     rerun x2, severity    HTML + MD     replay findings
                                                              evidence/     fixed / still open
                                                              promptfoo + garak exports
```

- **Evidence:** every finding keeps full transcripts in `evidence/`, with steps to reproduce and a fix.
- **Regression tests:** findings export to a `promptfooconfig.yaml` the client can run in CI.
- **Wider sweep:** a garak REST config is written for an extra automated pass.

## Quick start

```bash
pip install -r requirements.txt

# terminal 1: a deliberately insecure practice chatbot
python demo/vuln_bot.py

# terminal 2: full check, then open runs/demo/report.html
python -m aicheck run --config demo/demo.yaml --out runs/demo
```

Simulate the owner fixing some issues, then retest:

```bash
DEMO_FIXED=memory,agency,leak python demo/vuln_bot.py
python -m aicheck retest --config demo/demo.yaml --results runs/demo/results.json
```

### Practise against a real model

`demo/ai_bot.py` puts the same kinds of flaws around a real LLM, so results are noisy like a real product's.

```bash
ollama pull llama3.2                 # free, local (https://ollama.com)
python demo/ai_bot.py                # or AI_PROVIDER=anthropic with ANTHROPIC_API_KEY
python -m aicheck run --config demo/ai_demo.yaml --out runs/ai
```

Windows users can double-click `scripts/windows/run_ai_check.bat` and `run_ai_retest.bat`.

## Testing a real system

1. Get a signed permission letter that names the system, the test accounts and the dates.
2. Copy `demo/demo.yaml` to `clients/<name>.yaml` (`clients/` is git-ignored) and fill in:
   - `authorization`: letter path, dates, allowed hosts
   - `target`: the staging chat endpoint, a request body with `{{message}}` (and `{{document}}` if files are accepted), and `response_path` to the reply text, e.g. `choices.0.message.content`
   - two `users` with separate login headers, so cross-user leaks can be tested
   - `policy`, `known_secrets` (ask the owner to plant a dummy canary in staging) and, if available, `agency.action_log_url`
3. Run `python -m aicheck check-auth --config clients/<name>.yaml`, then `run`.
4. Review anything marked **needs review** or **manual**, confirm unsafe-output findings in the real UI, and spend time on manual testing of business logic before sending the report.

## Safety

- **Permission gate:** no request is sent unless the letter file exists, today is inside the agreed window, and every host is allow-listed.
- **Load limits:** burst tests are capped at 50 requests, with a configurable delay between probes.
- **Benign probes:** markers are random strings, and agency tests target `example.invalid` addresses.
- **Data handling:** test only with dummy data. Stop and report immediately if real customer data appears.

Testing systems without the owner's written permission may be illegal. This tool is for authorised assessments only.

## Tests

```bash
python -m pytest -q
```

The suite covers the permission gate, every detector type, and a full end-to-end run against the demo bot.

## Limitations

- Automated probes find common, well-known weaknesses. Business-logic flaws still need a human.
- LLM output is non-deterministic, so a passed test is not proof of safety.
- Unsafe-output findings prove the model returns the payload, not that the app renders it.
- Excessive-agency checks are strongest when the target exposes an action log; otherwise they are flagged for review.
- This is not a certification or audit opinion.

## Project layout

```
aicheck/
  config.py      config loading + permission gate
  target.py      generic HTTP chat adapter (templated body, dotted response path)
  recon.py       day 1: capability mapping
  probes.py      days 2-3: probe library mapped to OWASP LLM Top 10
  detectors.py   verdict logic (marker, canary, action-log diff, rate-limit, optional LLM judge)
  runner.py      execution, confirmation reruns, severity ranking, fix guidance
  report.py      founder summary, engineer findings, evidence, retest reports
  export.py      promptfoo and garak exports
  cli.py         run / retest / check-auth
demo/            insecure practice bots and configs
scripts/windows/ one-click run and retest scripts
tests/           pytest suite
docs/            sample report, retest and screenshot
```

## License

MIT. See [LICENSE](LICENSE).
