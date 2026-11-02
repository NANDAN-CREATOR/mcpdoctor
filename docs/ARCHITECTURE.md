# Architecture

```
            +-----------+     +------------------------------+
 CLI/Action |  runner   |---->| target (stdio cmd / URL /    |
  options   |  scan()   |     |  config file) + Isolation    |
            +-----+-----+     +------------------------------+
                  |
   1. start -> session.py (MCP client, stderr capture, timeouts, crash detection)
   2. list tools -> models.ToolInfo
   3. static:   lint.py (Q*)  security_static.py (S001-S006)  http_checks.py (S007-S009)  pin.py (S010)
   4. dynamic:  probes.py (D*, B001-B004, P002) - budgets, canaries, auto-restart, coverage table
   5. optional: evals/agent.py (B005-B006) via evals/llm.py (OpenAI-compatible HTTP)
   6. finish:   suppression (.mcpdoctor.yml) -> scoring.py -> Report
   7. report/:  terminal | json | sarif | markdown | html | badge          leaderboard.py (static site)
```

## Design decisions
- **Findings are evidence-backed.** Dynamic findings carry the request and the response snippet. Command injection is
  proven by a *computed* marker (`$((6*7))` -> `42`) that cannot appear by echoing the input.
- **Canaries, not real secrets.** The server's environment, fake HOME and workdir contain unique tokens; seeing one in
  any output proves a leak with no false positives.
- **Coverage is part of the report.** Every check records `ran`, `skipped` or `n/a` with the reason.
- **Precision over recall in the metadata scan.** Phrases like "ignore" or "do not" appear in honest descriptions, so
  S001 needs an instruction-hijacking pattern, not a keyword.
- **Safe by default.** Destructive-looking tools are skipped unless `--probe-all`; call, time and output budgets apply.
- **No telemetry.** The only network traffic is to the server under test, and to an LLM endpoint if you ask for one.

## Threat model (what the scanner defends itself against)
A hostile server can: print terminal escape codes (stripped before display), return huge responses (reported as D010; not truncated before they are read), hang (call timeouts; the session is closed and restarted), crash (restart up to 3 times), or embed HTML in names (reports are escaped). It cannot read your
files or environment unless you run it without `--sandbox` and the server is malicious code - hence the sandbox.
