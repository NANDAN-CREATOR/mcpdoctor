# Rule reference

Generated from `src/mcpdoctor/rules.py` by `scripts/gen_rules_doc.py`. Do not edit by hand.

| ID | Severity | Category | Runs tools | Title |
|---|---|---|---|---|
| [P001](#p001) | critical | protocol | no | Server failed to start or initialize |
| [P002](#p002) | high | protocol | yes | Server crashed or hung while being tested |
| [P003](#p003) | low | protocol | no | Slow startup |
| [P004](#p004) | low | protocol | no | Server exposes no tools |
| [Q001](#q001) | high | quality | no | Tool has no description |
| [Q002](#q002) | medium | quality | no | Tool description too short to guide an agent |
| [Q003](#q003) | low | quality | no | Tool description is very long |
| [Q004](#q004) | low | quality | no | No guidance on when to use (or not use) the tool |
| [Q005](#q005) | medium | quality | no | Parameter has no description |
| [Q006](#q006) | medium | quality | no | Parameter has no type |
| [Q007](#q007) | low | quality | no | Free-form string where a constrained format is expected |
| [Q008](#q008) | low | quality | no | Two tools overlap too closely |
| [Q009](#q009) | low | quality | no | Vague tool name |
| [Q010](#q010) | info | quality | no | Inconsistent tool naming convention |
| [Q011](#q011) | low | quality | no | No behaviour annotations |
| [Q012](#q012) | high | quality | no | Annotations contradict what the tool does |
| [Q013](#q013) | low | quality | no | Too many tools |
| [Q014](#q014) | low | quality | no | Tool definitions consume a large share of context |
| [Q015](#q015) | info | quality | no | Tool has no output schema |
| [S001](#s001) | high | security | no | Instruction hijacking text in tool metadata |
| [S002](#s002) | high | security | no | Invisible or bidirectional control characters in metadata |
| [S003](#s003) | medium | security | no | Encoded payload in tool metadata |
| [S004](#s004) | medium | security | no | Tool metadata tries to steer other tools (shadowing) |
| [S005](#s005) | high | security | no | Arbitrary command or code execution surface |
| [S006](#s006) | critical | security | no | Credential or secret embedded in tool definitions |
| [S007](#s007) | high | security | no | Remote server reached over cleartext HTTP |
| [S008](#s008) | high | security | yes | Remote endpoint accepts unauthenticated requests |
| [S009](#s009) | medium | security | yes | Remote endpoint does not validate the Origin header |
| [S010](#s010) | high | security | no | Tool definitions changed since they were pinned |
| [D001](#d001) | high | security | yes | Path traversal / unconfined file access |
| [D002](#d002) | high | security | yes | Server-side request forgery (SSRF) |
| [D003](#d003) | high | security | yes | SQL injection or raw SQL errors reach the caller |
| [D004](#d004) | medium | security | yes | Stacked SQL statements are executed |
| [D005](#d005) | high | security | yes | Read-only claim violated: a write succeeded |
| [D006](#d006) | critical | security | yes | OS command injection |
| [D007](#d007) | medium | security | yes | Error responses leak internals |
| [D008](#d008) | critical | security | yes | Environment or secrets leaked in tool output |
| [D009](#d009) | low | security | yes | Tool accepts input that violates its own schema |
| [D010](#d010) | medium | security | yes | Unbounded response size |
| [D011](#d011) | high | security | yes | Tool definitions changed during the session |
| [B001](#b001) | high | behavior | yes | A schema-valid call fails (schema does not match behaviour) |
| [B002](#b002) | medium | behavior | yes | Result does not match the declared output schema |
| [B003](#b003) | low | behavior | yes | Slow tool |
| [B004](#b004) | low | behavior | yes | Error message is not actionable |
| [B005](#b005) | medium | behavior | yes | Agent selects the wrong tool for a task |
| [B006](#b006) | medium | behavior | yes | Agent produces invalid arguments |

<a id="p001"></a>
## P001 - Server failed to start or initialize

- **Default severity:** critical
- **Category:** protocol
- **Executes tools:** no

**Why it matters.** If the server cannot complete the MCP handshake no client can use it.

**How to fix.** Run the command by hand, read stderr, and make sure stdout carries only MCP protocol messages.

<a id="p002"></a>
## P002 - Server crashed or hung while being tested

- **Default severity:** high
- **Category:** protocol
- **Executes tools:** yes
- **References:** CWE-248, CWE-400

**Why it matters.** A server that dies or stops answering on unusual input lets any caller take the tool offline.

**How to fix.** Catch exceptions per tool call, return an MCP error result, and enforce timeouts on slow work.

<a id="p003"></a>
## P003 - Slow startup

- **Default severity:** low
- **Category:** protocol
- **Executes tools:** no

**Why it matters.** Clients wait for the handshake and tool listing before the first call; slow starts time out.

**How to fix.** Defer heavy initialisation until the first tool call (lazy loading).

<a id="p004"></a>
## P004 - Server exposes no tools

- **Default severity:** low
- **Category:** protocol
- **Executes tools:** no

**Why it matters.** A tools-only scan has nothing to test. The server may only expose resources or prompts.

**How to fix.** Expose at least one tool, or ignore this finding if the server is resources/prompts only.

<a id="q001"></a>
## Q001 - Tool has no description

- **Default severity:** high
- **Category:** quality
- **Executes tools:** no

**Why it matters.** The description is the only thing a model has to decide whether to call the tool.

**How to fix.** Add a one-to-three sentence description that says what the tool does and what it returns.

<a id="q002"></a>
## Q002 - Tool description too short to guide an agent

- **Default severity:** medium
- **Category:** quality
- **Executes tools:** no

**Why it matters.** Very short descriptions do not say what the tool does, what it returns, or when it applies.

**How to fix.** State the action, the data it works on, and what the result contains (aim for 40+ characters).

<a id="q003"></a>
## Q003 - Tool description is very long

- **Default severity:** low
- **Category:** quality
- **Executes tools:** no

**Why it matters.** Long descriptions consume context on every request and bury the useful sentence.

**How to fix.** Keep descriptions under about 1,200 characters; move reference material to a resource.

<a id="q004"></a>
## Q004 - No guidance on when to use (or not use) the tool

- **Default severity:** low
- **Category:** quality
- **Executes tools:** no

**Why it matters.** Agents choose between tools using the descriptions; without boundaries they pick the wrong tool.

**How to fix.** Add a 'Use when...' / 'Do not use for...' sentence that separates the tool from its neighbours.

<a id="q005"></a>
## Q005 - Parameter has no description

- **Default severity:** medium
- **Category:** quality
- **Executes tools:** no

**Why it matters.** Models guess parameter meaning from the name alone, which causes invalid or wrong arguments.

**How to fix.** Add a description (with units, format and an example) to every parameter.

<a id="q006"></a>
## Q006 - Parameter has no type

- **Default severity:** medium
- **Category:** quality
- **Executes tools:** no

**Why it matters.** An untyped parameter lets the model send anything and the server cannot validate it.

**How to fix.** Declare 'type' (or 'enum' / 'anyOf') for every property in the input schema.

<a id="q007"></a>
## Q007 - Free-form string where a constrained format is expected

- **Default severity:** low
- **Category:** quality
- **Executes tools:** no

**Why it matters.** Paths, URLs, ids and dates accepted as unconstrained strings invite malformed and hostile input.

**How to fix.** Add 'pattern', 'format', 'enum', 'minLength'/'maxLength' to the schema and validate on the server.

<a id="q008"></a>
## Q008 - Two tools overlap too closely

- **Default severity:** low
- **Category:** quality
- **Executes tools:** no

**Why it matters.** Near-duplicate tools make tool selection a coin toss for the model.

**How to fix.** Merge them, or make each description say what distinguishes it from the other.

<a id="q009"></a>
## Q009 - Vague tool name

- **Default severity:** low
- **Category:** quality
- **Executes tools:** no

**Why it matters.** Names such as 'run' or 'tool1' say nothing about the action and collide across servers.

**How to fix.** Use a verb_noun name that describes the action (for example 'search_issues').

<a id="q010"></a>
## Q010 - Inconsistent tool naming convention

- **Default severity:** info
- **Category:** quality
- **Executes tools:** no

**Why it matters.** Mixed snake_case / camelCase / kebab-case makes a tool set harder for models and humans to predict.

**How to fix.** Pick one naming convention for all tools.

<a id="q011"></a>
## Q011 - No behaviour annotations

- **Default severity:** low
- **Category:** quality
- **Executes tools:** no

**Why it matters.** Without readOnlyHint / destructiveHint, clients cannot ask for confirmation sensibly.

**How to fix.** Set read_only_hint and destructive_hint on every tool.

<a id="q012"></a>
## Q012 - Annotations contradict what the tool does

- **Default severity:** high
- **Category:** quality
- **Executes tools:** no

**Why it matters.** A tool marked read-only whose name or description says it modifies data will skip human confirmation.

**How to fix.** Fix the annotation or the tool: read_only_hint must be false for anything that writes, sends or deletes.

<a id="q013"></a>
## Q013 - Too many tools

- **Default severity:** low
- **Category:** quality
- **Executes tools:** no

**Why it matters.** Model accuracy drops as the tool list grows, and every tool costs context tokens.

**How to fix.** Split into several focused servers, or expose fewer, broader tools.

<a id="q014"></a>
## Q014 - Tool definitions consume a large share of context

- **Default severity:** low
- **Category:** quality
- **Executes tools:** no

**Why it matters.** The full tool list is sent with every model request.

**How to fix.** Trim descriptions and schemas; drop rarely used parameters.

<a id="q015"></a>
## Q015 - Tool has no output schema

- **Default severity:** info
- **Category:** quality
- **Executes tools:** no

**Why it matters.** Without an output schema clients cannot validate results or let the model plan on the shape.

**How to fix.** Declare an output schema and return structured content.

<a id="s001"></a>
## S001 - Instruction hijacking text in tool metadata

- **Default severity:** high
- **Category:** security
- **Executes tools:** no
- **References:** OWASP-LLM01

**Why it matters.** Hidden instructions in tool descriptions or schemas are read by the model as trusted guidance (tool poisoning). Typical forms: override of earlier instructions, concealment from the user, reading sensitive files, or sending data to a URL.

**How to fix.** Remove the text. Descriptions must only describe the tool's own behaviour.

<a id="s002"></a>
## S002 - Invisible or bidirectional control characters in metadata

- **Default severity:** high
- **Category:** security
- **Executes tools:** no
- **References:** OWASP-LLM01, CWE-116

**Why it matters.** Zero-width, bidi-override and Unicode tag characters hide instructions from human reviewers while the model still reads them.

**How to fix.** Strip the characters; reject them in a CI check.

<a id="s003"></a>
## S003 - Encoded payload in tool metadata

- **Default severity:** medium
- **Category:** security
- **Executes tools:** no
- **References:** OWASP-LLM01

**Why it matters.** Long base64 / hex blobs in descriptions are a common way to smuggle instructions past review.

**How to fix.** Remove the blob or move legitimate binary data out of descriptions.

<a id="s004"></a>
## S004 - Tool metadata tries to steer other tools (shadowing)

- **Default severity:** medium
- **Category:** security
- **Executes tools:** no
- **References:** OWASP-LLM01

**Why it matters.** A description that tells the model how to use or avoid a different tool can hijack that tool's behaviour.

**How to fix.** Describe only this tool. Never reference other tools' names with directives.

<a id="s005"></a>
## S005 - Arbitrary command or code execution surface

- **Default severity:** high
- **Category:** security
- **Executes tools:** no
- **References:** CWE-78, CWE-94, OWASP-LLM06

**Why it matters.** A tool that runs caller-supplied shell commands, code or raw SQL gives the model (and anyone who can inject text into its context) the full power of the server's account.

**How to fix.** Replace with narrow, parameterised tools, or run in a sandbox with explicit human approval.

<a id="s006"></a>
## S006 - Credential or secret embedded in tool definitions

- **Default severity:** critical
- **Category:** security
- **Executes tools:** no
- **References:** CWE-798

**Why it matters.** Tool metadata is sent to every connected client, so an embedded key is effectively published.

**How to fix.** Rotate the secret immediately and load credentials from the environment at call time.

<a id="s007"></a>
## S007 - Remote server reached over cleartext HTTP

- **Default severity:** high
- **Category:** security
- **Executes tools:** no
- **References:** CWE-319

**Why it matters.** Tool calls and results (which often contain credentials and private data) can be read or altered in transit.

**How to fix.** Serve over HTTPS.

<a id="s008"></a>
## S008 - Remote endpoint accepts unauthenticated requests

- **Default severity:** high
- **Category:** security
- **Executes tools:** yes
- **References:** CWE-306

**Why it matters.** Anyone who can reach the URL can list and call every tool. (Reported as info instead of high when every tool looks read-only, because open access is normal for public documentation or search services.)

**How to fix.** Require OAuth 2.1 / bearer tokens on the MCP endpoint.

<a id="s009"></a>
## S009 - Remote endpoint does not validate the Origin header

- **Default severity:** medium
- **Category:** security
- **Executes tools:** yes
- **References:** CWE-346

**Why it matters.** Without Origin validation a malicious web page can drive a local server through the browser (DNS rebinding).

**How to fix.** Reject requests whose Origin is not on an allow-list, and bind to 127.0.0.1 for local servers.

<a id="s010"></a>
## S010 - Tool definitions changed since they were pinned

- **Default severity:** high
- **Category:** security
- **Executes tools:** no
- **References:** OWASP-LLM01

**Why it matters.** A tool whose description changes after you approved it can turn malicious later (rug pull).

**How to fix.** Review the diff. If it is legitimate, re-run 'mcpdoctor pin' and commit the new lock file.

<a id="d001"></a>
## D001 - Path traversal / unconfined file access

- **Default severity:** high
- **Category:** security
- **Executes tools:** yes
- **References:** CWE-22

**Why it matters.** The tool returned the contents of files outside any sensible root when given '../' or absolute paths.

**How to fix.** Resolve the path, then require that it is inside an allowed root before opening it.

<a id="d002"></a>
## D002 - Server-side request forgery (SSRF)

- **Default severity:** high
- **Category:** security
- **Executes tools:** yes
- **References:** CWE-918

**Why it matters.** The server fetched an attacker-chosen URL pointing at the loopback interface. The same bug reaches cloud metadata endpoints and internal services.

**How to fix.** Resolve the host first and refuse loopback, link-local and private ranges (and re-check after redirects).

<a id="d003"></a>
## D003 - SQL injection or raw SQL errors reach the caller

- **Default severity:** high
- **Category:** security
- **Executes tools:** yes
- **References:** CWE-89

**Why it matters.** A quote character in a search parameter produced a database syntax error, which means the value is concatenated into the query.

**How to fix.** Use parameterised queries for every value.

<a id="d004"></a>
## D004 - Stacked SQL statements are executed

- **Default severity:** medium
- **Category:** security
- **Executes tools:** yes
- **References:** CWE-89

**Why it matters.** A tool that runs 'SELECT 1; SELECT 2' will also run '...; DROP TABLE ...'.

**How to fix.** Execute exactly one statement per call and reject statements containing ';' outside literals.

<a id="d005"></a>
## D005 - Read-only claim violated: a write succeeded

- **Default severity:** high
- **Category:** security
- **Executes tools:** yes
- **References:** CWE-89, CWE-284

**Why it matters.** The tool is described or annotated as read-only but accepted a data-changing statement.

**How to fix.** Open the database read-only, or use a role with no write privileges.

<a id="d006"></a>
## D006 - OS command injection

- **Default severity:** critical
- **Category:** security
- **Executes tools:** yes
- **References:** CWE-78

**Why it matters.** Shell metacharacters in a parameter were executed by the server.

**How to fix.** Never pass parameters through a shell. Use argument lists (no shell=True) and validate input.

<a id="d007"></a>
## D007 - Error responses leak internals

- **Default severity:** medium
- **Category:** security
- **Executes tools:** yes
- **References:** CWE-209

**Why it matters.** Stack traces, file-system paths and library versions in error text help attackers and bloat model context.

**How to fix.** Return a short, actionable message to the client and log the traceback server-side.

<a id="d008"></a>
## D008 - Environment or secrets leaked in tool output

- **Default severity:** critical
- **Category:** security
- **Executes tools:** yes
- **References:** CWE-200, CWE-532

**Why it matters.** A planted canary secret placed in the server's environment appeared in a tool response.

**How to fix.** Never return os.environ or config dumps. Redact secrets and expose only whitelisted values.

<a id="d009"></a>
## D009 - Tool accepts input that violates its own schema

- **Default severity:** low
- **Category:** security
- **Executes tools:** yes
- **References:** CWE-20

**Why it matters.** Wrong-typed arguments were accepted, so the schema is documentation only and not enforced.

**How to fix.** Validate arguments against the input schema before running the tool.

<a id="d010"></a>
## D010 - Unbounded response size

- **Default severity:** medium
- **Category:** security
- **Executes tools:** yes
- **References:** CWE-770

**Why it matters.** A large 'limit'-style argument produced an enormous response that can flood the model's context window.

**How to fix.** Cap page sizes server-side and return a continuation cursor.

<a id="d011"></a>
## D011 - Tool definitions changed during the session

- **Default severity:** high
- **Category:** security
- **Executes tools:** yes
- **References:** OWASP-LLM01

**Why it matters.** The tool list differed after tools were called, which is the signature of a runtime rug pull.

**How to fix.** Tool definitions must be stable for a session; announce changes via list_changed and keep them benign.

<a id="b001"></a>
## B001 - A schema-valid call fails (schema does not match behaviour)

- **Default severity:** high
- **Category:** behavior
- **Executes tools:** yes

**Why it matters.** MCPDoctor built arguments from the tool's own input schema and the call was rejected or crashed. Agents trust the schema, so they will hit the same failure.

**How to fix.** Make the schema match what the code accepts (required fields, enums, formats).

<a id="b002"></a>
## B002 - Result does not match the declared output schema

- **Default severity:** medium
- **Category:** behavior
- **Executes tools:** yes

**Why it matters.** Clients that validate structured output will reject the result.

**How to fix.** Return data that conforms to the output schema, or fix the schema.

<a id="b003"></a>
## B003 - Slow tool

- **Default severity:** low
- **Category:** behavior
- **Executes tools:** yes

**Why it matters.** Slow tool calls stall agent loops and trigger client timeouts.

**How to fix.** Stream progress, add pagination, or move long work to an async job.

<a id="b004"></a>
## B004 - Error message is not actionable

- **Default severity:** low
- **Category:** behavior
- **Executes tools:** yes

**Why it matters.** An agent can only recover from a failure if the message says what was wrong and how to fix it.

**How to fix.** Return what was invalid and what a valid value looks like.

<a id="b005"></a>
## B005 - Agent selects the wrong tool for a task

- **Default severity:** medium
- **Category:** behavior
- **Executes tools:** yes

**Why it matters.** In the LLM evaluation, a model given a realistic user request chose a different tool than intended.

**How to fix.** Sharpen the descriptions of the confused tools and add 'use when / do not use' guidance.

<a id="b006"></a>
## B006 - Agent produces invalid arguments

- **Default severity:** medium
- **Category:** behavior
- **Executes tools:** yes

**Why it matters.** In the LLM evaluation, arguments chosen by the model did not validate against the input schema.

**How to fix.** Add parameter descriptions, examples, enums and formats.
