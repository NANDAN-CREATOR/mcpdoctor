# MCPDoctor

**Test any MCP server before you trust it, or before you ship it.**

MCP (Model Context Protocol) servers give AI agents tools: read files, query databases, call APIs. Most are written
quickly and never tested. MCPDoctor connects to a server like an agent would, then tells you whether its tools are
**well described** (so an agent picks the right one), **safe** (no injection, leaks or poisoned descriptions) and
**reliable** (no crashes, no silent failures) and gives it one 0-100 score you can gate CI on.

Free, open source (MIT), no telemetry, no paid services needed. Python 3.11+.

```text
$ mcpdoctor scan -- python examples/servers/bad_exec.py
SCORE 43/100  F    (security 0 F | quality 77 C | reliability 96 A)
FINDINGS (12)  3 critical, 1 high, 3 medium, 5 low
  CRITICAL D006 ping_host   OS command injection
      Tool 'ping_host' parameter 'host' executed shell syntax: the computed marker MCPDOCTOR_42
      appeared in the output for payload '; echo MCPDOCTOR_$((6*7))'.
  CRITICAL D008 debug_info  Environment or secrets leaked in tool output
  CRITICAL S006 connect_service  Credential or secret embedded in tool definitions
  HIGH     S005 run_command  Arbitrary command or code execution surface
```

---

## Contents
1. [Who it is for](#who-it-is-for) · 2. [Requirements](#requirements) · 3. [Quick start](#quick-start) ·
4. [How it works](#how-it-works) · 5. [What it checks](#what-it-checks) · 6. [How scoring works](#how-scoring-works) ·
7. [CLI reference](#cli-reference) · 8. [Configuration](#configuration) · 9. [Use in CI](#use-in-ci-github) ·
10. [Sandbox](#sandbox) · 11. [LLM agent evaluation](#llm-agent-evaluation) · 12. [Reports](#reports) ·
13. [Expectations: what it can and cannot tell you](#expectations-what-it-can-and-cannot-tell-you) ·
14. [Measured results](#measured-results) · 15. [Project layout](#project-layout) · 16. [Status and roadmap](#status-and-roadmap)

## Who it is for
| You are... | You use it to... |
|---|---|
| Writing an MCP server | Catch vague descriptions and bugs before agents hit them; gate pull requests on a score. |
| Adding third-party servers to Claude / Cursor / VS Code | Check a server for poisoned tool descriptions, leaks and injection holes before you connect it. |
| Running a platform or registry | Scan many servers nightly and publish a leaderboard (built in). |
| Researching agent safety | Reproducible rules with CWE/OWASP references and a defect corpus to benchmark against. |

## Requirements

**To run MCPDoctor**
- Python **3.11 or newer** (tested on 3.13 here; CI matrix covers 3.11-3.13 on Linux and macOS).
- The official MCP Python SDK **v2** (installed automatically as `mcp>=2.0,<3`).
- Whatever your own server needs (Node for an `npx` server, your Python venv, and so on) on the same machine.

**Optional**
| Feature | Needs |
|---|---|
| `--sandbox` | Docker with a running daemon, and an image that contains your server. |
| `--llm` agent evaluation | An OpenAI-compatible endpoint: free API key from Gemini, Groq or OpenRouter, or a local Ollama model. |
| CI / SARIF upload | A GitHub repository (code scanning is free for public repos). |

**Cost: $0.** There is no hosted component.

**Permissions you are granting.** `mcpdoctor scan` *starts the server and calls its tools*. Treat that like running the
server yourself. Use `--static-only` (never calls a tool) or `--sandbox` for code you do not trust.

## Quick start
```bash
pip install -e .            # from a clone; `pip install mcpdoctor` once published
mcpdoctor check-env         # versions, Docker availability, which LLM keys are set

# local server over stdio (everything after -- is the command)
mcpdoctor scan -- python my_server.py
mcpdoctor scan -- npx -y @modelcontextprotocol/server-filesystem /tmp/x

# remote server
mcpdoctor scan --url https://example.com/mcp --header "Authorization=Bearer $TOKEN"

# every server in a Claude Desktop / Cursor / VS Code config
mcpdoctor scan --mcp-config ~/.cursor/mcp.json --all --html report.html

# only read definitions, never call a tool
mcpdoctor scan --static-only -- python my_server.py
```
Try the bundled examples (one clean server and six deliberately broken ones) in `examples/servers/`.

## How it works
A scan runs in stages. Each stage writes to a **coverage table** so you can see what ran, what was skipped and why.

1. **Connect.** Starts the server (stdio) or opens a Streamable HTTP session, captures stderr, applies timeouts,
   reads server identity and the tool list.
2. **Static analysis** (no tool is called)
   - *Lint* (Q rules): descriptions, parameter docs, types, naming, annotations, size.
   - *Metadata security scan* (S001-S006): hidden instructions, invisible/bidi characters, encoded payloads,
     cross-tool shadowing, secrets, command-execution surfaces.
   - *Remote checks* (S007-S009): cleartext HTTP, anonymous access, Origin validation.
   - *Pinning* (S010): compare against a lock file to catch "rug pulls".
3. **Dynamic probes** (tools are called, within budgets). The server runs with a **fake HOME**, an **empty working
   directory** and **canary secrets** planted in files and environment variables:
   | Probe | Method | Proof |
   |---|---|---|
   | contract | Calls each tool with arguments generated from its own JSON Schema, 3x | Failure of a valid call (B001), latency (B003), error quality (B004) |
   | input-validation | Wrong types, missing required fields | Server accepted invalid input (D009) |
   | env-leak | Canary tokens in env and files | Canary value seen in any output (D008/D001) |
   | path-traversal | `../` and absolute paths into path-like params | `/etc/passwd` pattern or canary file content returned (D001) |
   | ssrf | URL params pointed at a loopback listener MCPDoctor owns | The listener received a request (D002) |
   | sql | Quote/stacked-statement payloads; write attempt with `--probe-all` | SQL error text (D003), second statement ran (D004), write succeeded (D005) |
   | command-injection | `; echo MCPDOCTOR_$((6*7))` | The *computed* `MCPDOCTOR_42` appears: echoing the input cannot produce it (D006) |
   | unbounded-output | Huge `limit`/`count` values | Response over 200 kB (D010) |
   | definition-drift | Re-read the tool list after the calls | Definitions changed mid-session (D011) |
   | robustness | Very long string, NUL byte, empty string | Crash (P002), leaked traces (D007) |

   Safety rails: destructive-looking tools (by name or annotation) are skipped unless `--probe-all`; a cap on calls
   (default 700) and on time (default 300 s); a crashed server is restarted up to 3 times; a hung call is timed out.
4. **Optional agent evaluation**: a real LLM is given your tools and realistic requests; MCPDoctor measures how often
   it picks the right tool and produces valid arguments (B005/B006).
5. **Score and report**: suppressions from `.mcpdoctor.yml` are applied, findings scored, reports written.

## What it checks
46 rules; each has a plain-language explanation, fix advice and CWE/OWASP references. Run `mcpdoctor rules` for the list,
`mcpdoctor rules D006` for one, or read [docs/RULES.md](docs/RULES.md).

| Group | Rules | Examples |
|---|---|---|
| **P** protocol | 4 | P001 server failed to start; P002 crash or hang |
| **Q** quality | 15 | Q001 no description; Q005 undocumented parameter; Q008 two tools overlap; Q012 annotation says read-only but name says delete |
| **S** security (static + transport) | 10 | S001 instruction hijacking in metadata; S002 invisible characters; S005 arbitrary-exec tool; S006 embedded credential; S008 unauthenticated remote |
| **D** security (dynamic) | 11 | D001 path traversal; D002 SSRF; D003-D005 SQL; D006 command injection; D008 secret leak |
| **B** behaviour | 6 | B001 valid call fails; B003 slow; B004 unhelpful error; B005/B006 agent mistakes |

## How scoring works
- Every finding has a severity cost: **critical 40, high 20, medium 8, low 3, info 0**.
- Cost is scaled by confidence (high 1.0, medium 0.6, low 0.3) and by repetition: the first hit of a rule counts fully,
  the second half, later ones a quarter, so one sloppy habit across 30 tools cannot drown everything else.
- Three category scores start at 100 and lose their cost: **security 50%**, **quality 25%**, **reliability 25%** of the overall.
  A category that was not tested (with `--static-only`, reliability is not tested) is excluded and
  the report says "not tested" instead of awarding free points. Static-only security scores therefore cover only the static checks.
- **Caps:** any critical finding limits the overall score to 49; a high security finding to 74; any high finding to 84.
- **Grades:** A >= 90, B >= 80, C >= 70, D >= 60, otherwise F.
- Default gate: exit status 1 if any finding is **high or above**. Change with `--fail-on` / `--min-score`.

## CLI reference
```text
mcpdoctor scan [OPTIONS] [-- COMMAND...]
```
| Option | Meaning |
|---|---|
| `-- COMMAND` / `--url URL` / `--mcp-config FILE` | The target (exactly one). With a config file add `--server NAME` or `--all`. |
| `--header K=V`, `--env K=V`, `--pass-env NAME` | Headers for remote servers; environment for the server; forward a variable from your shell. |
| `--static-only` | Never call a tool. |
| `--probe-all` | Also call destructive-looking tools (use inside `--sandbox`). |
| `--probes a,b` | Subset of: contract, input-validation, env-leak, path-traversal, sql, command-injection, ssrf, unbounded-output, definition-drift, robustness. |
| `--repeats N`, `--max-calls N`, `--time-budget S`, `--call-timeout S`, `--slow-ms MS` | Budgets and thresholds. |
| `--sandbox --image IMG [--mount H:C[:ro\|rw]] [--sandbox-network none\|bridge]` | Run the server in Docker. |
| `--lockfile FILE` | Compare tool definitions with a pinned file (S010). |
| `--llm PROVIDER [--model M] [--llm-base-url U] [--llm-key-env VAR] [--llm-rpm N] [--eval-tasks N] [--tasks-file F] [--eval-execute]` | Agent evaluation. |
| `--format terminal\|json\|sarif\|markdown\|html`, `-o FILE` | Primary output. |
| `--json F`, `--sarif F`, `--markdown F`, `--html F`, `--badge F` | Extra outputs in the same run (suffixed with the server name when scanning several). |
| `--fail-on SEVERITY`, `--min-score N` | CI gate. |
| `--settings FILE`, `-v`, `--min-severity S` | Settings file, detail level. |

Other commands: `mcpdoctor pin -- CMD` (write `mcpdoctor.lock.json`), `rules [ID]`, `init` (settings file + workflow),
`leaderboard servers.yaml --out site`, `check-env`.

**Exit codes:** `0` gate passed, `1` gate failed, `2` usage or setup error (bad arguments, missing Docker, unknown rule).

## Configuration
`.mcpdoctor.yml` in the working directory (or `--settings`):
```yaml
fail_on: high            # none | info | low | medium | high | critical
min_score: 80
slow_ms: 3000
max_calls: 400
ignore:
  - Q015                       # ignore a rule everywhere
  - rule: Q011                 # ignore it for one tool only
    tool: legacy_tool
lint:                          # thresholds for quality rules (see LintConfig)
  max_tools: 40
```
Unknown rule ids and keys are errors, so a typo cannot silently disable a check.

## Use in CI (GitHub)
```yaml
# .github/workflows/mcpdoctor.yml   (or run `mcpdoctor init`)
on: [pull_request]
permissions: { contents: read, security-events: write, pull-requests: write }
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with: { python-version: "3.12" }
      - run: pip install -r requirements.txt
      - uses: NANDAN-CREATOR/mcpdoctor@v0
        with:
          command: python server.py
          fail-on: high
          min-score: 80
```
The action fails the job on the gate, uploads **SARIF** to the repository's Security tab, posts the Markdown report as a
sticky PR comment and writes it to the job summary. Outputs: `score`, `grade`.

Repository workflows included: `ci.yml` (lint, types, tests on 3 Python versions x 2 OSes, docs freshness, Docker sandbox
job), `release.yml` (tag -> PyPI trusted publishing + GHCR image + GitHub Release), `nightly-leaderboard.yml`
(scan `examples/leaderboard-servers.yaml` -> GitHub Pages), `self-test.yml` (the action scans the clean demo server).

## Sandbox
```bash
docker build -t my-server .                         # your server + its dependencies
mcpdoctor scan --sandbox --image my-server --probe-all -- python /app/server.py
```
The container runs with: no network, read-only root, 64 MB `noexec` tmpfs, all capabilities dropped,
`no-new-privileges`, non-root user, PID/memory/CPU limits, and MCPDoctor's fake HOME and empty workdir mounted read-only.
Extra mounts are read-only unless you write `:rw`. `--sandbox-network bridge` is needed for servers that must reach
the internet, which also weakens SSRF containment.
Only stdio targets can be sandboxed; MCPDoctor does not run remote servers.

## LLM agent evaluation
Static checks tell you a description *looks* fine. This asks a real model whether it *works*.
```bash
export GEMINI_API_KEY=...     # free tier at aistudio.google.com   (or GROQ_API_KEY / OPENROUTER_API_KEY)
mcpdoctor scan --llm gemini --tasks-file eval-tasks.json -- python my_server.py
mcpdoctor scan --llm ollama --model qwen3:8b -- python my_server.py        # fully local
```
1. The model writes realistic user requests for each tool (without naming it).
2. Each request is sent with all your tools; MCPDoctor records the tool chosen and validates the arguments against the schema.
3. Output: tool-selection accuracy, argument validity, a confusion list ("asked for X, model chose Y") and findings B005/B006.
`--tasks-file` caches the generated requests keyed by tool definition so later runs are repeatable and cost fewer requests.
`--eval-execute` additionally runs the chosen call (safe tools only unless `--probe-all`).
Rate limits are respected (`--llm-rpm`, default 15; retries on 429/5xx). API keys are read from the environment and never
printed or written to reports. Default model names are in `evals/llm.py` and may go stale: pass `--model`.

## Reports
| Format | Use |
|---|---|
| terminal | Humans; control characters in server-supplied text are stripped |
| JSON | Machines; stable schema including coverage and evaluation data |
| SARIF 2.1.0 | GitHub code scanning; rules carry `security-severity`, CWE tags, help text |
| Markdown | PR comments, job summaries |
| HTML | Single self-contained file (no external assets); content is escaped |
| SVG badge | `![score](badge.svg)` in your README |

## Expectations: what it can and cannot tell you
**It can tell you**
- Concrete, reproducible defects, each with evidence: the payload sent and the response seen.
- Which checks actually ran. **Read the coverage table**: "skipped" and "n/a" lines are the gaps.
- Whether a change made things better or worse (the score is deterministic for a given server and options, apart from the LLM evaluation).

**It cannot tell you**
- That a server is **safe**. A clean report means these checks found nothing, not that nothing is there.
  Authorization logic, business-logic flaws, data-dependent bugs and anything needing credentials it does not have are out of reach.
- Anything about tools it skipped as destructive-looking (unless `--probe-all`) or parameters it could not recognise.
- Whether a prompt-injection *description* is malicious in intent. S001 flags the pattern; a human decides.
- How a particular model behaves in production. The LLM evaluation measures the one model you pick, with a small sample.
- It is not a replacement for a security review, a pen test, or reading the code of a server you will give access to secrets.

**Known limitations in this version**
- The command-injection probe assumes a POSIX shell; Windows `cmd`/PowerShell injection is not tested.
- Servers that require OAuth to initialize can be reached only if you supply a bearer header.
- Probing stdio servers that print non-protocol text to stdout will fail at P001 (that is itself a bug in the server).
- Oversized responses are reported (D010) but not truncated before being read.
- **Not yet verified end to end in the environment this was built in:** the Docker sandbox (no Docker daemon was
  available; the `docker run` command construction is unit-tested, and `ci.yml` runs a real sandbox job) and real LLM
  providers (the evaluation is tested against a local mock OpenAI-compatible server; provider model names may need `--model`).
- Heuristic checks can false-positive. Use the `ignore` setting, with a comment on why.

## Measured results
Run `pytest -q -s tests/test_corpus.py` to reproduce.

| Server (examples/servers) | Planted defects | Detected | Score |
|---|---|---|---|
| `good_server.py` (clean) | 0 | 0 findings | 100 / A |
| `bad_poisoned.py` | S001 S002 S003 S004 S006 | 5 / 5 | 31 / F (static) |
| `bad_files.py` | D001 D002 D007 | 3 / 3 | 65 / D |
| `bad_sql.py` | D003 D004 D005 S005 | 4 / 4 | 74 / C |
| `bad_exec.py` | D006 S005 D008 S006 | 4 / 4 | 43 / F |
| `bad_quality.py` | 15 quality / behaviour rules | 15 / 15 | 46 / F |
| `bad_crash.py` | P002 | 1 / 1 | capped at 84 |

**32 / 32 planted defect classes found; 0 findings on the clean server.** This is a *self-built corpus*, written by the
same author as the detectors, so it shows the rules work as designed, **not** a measured false-negative rate against
real-world servers. Scanning independent public servers and recording the false-positive rate is the first roadmap item.

Test suite: 67 passing (1 Docker test skipped without a daemon), `ruff` and `mypy` clean.

## Project layout
```
src/mcpdoctor/   cli.py runner.py session.py target.py rules.py models.py scoring.py
                 lint.py security_static.py http_checks.py probes.py synth.py pin.py sandbox.py
                 settings.py leaderboard.py evals/{llm,agent}.py report/{terminal,json,sarif,markdown,html,badge}.py
examples/servers/ one clean server, six broken ones, and an HTTP variant
tests/           corpus benchmark, unit tests, mock-LLM test, HTTP tests
docs/            ARCHITECTURE.md  RULES.md (generated)
.github/         ci, release, nightly leaderboard, self-test        action.yml   Dockerfile   sandbox/Dockerfile
```
See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md), [CONTRIBUTING.md](CONTRIBUTING.md), [SECURITY.md](SECURITY.md).

## Status and roadmap
Version 0.1.0, pre-release. Next, in order:
1. Scan 20+ public servers; publish false-positive/negative notes and tune the rules.
2. Verify the sandbox and two real LLM providers end to end; record results here.
3. Baseline files (accept existing findings, fail only on new ones).
4. Windows shell injection probes; OAuth flow support; resource and prompt checks (tools only today).

License: MIT.
