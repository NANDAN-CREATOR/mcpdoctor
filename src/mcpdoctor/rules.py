"""The rule catalog.

Every check MCPDoctor performs is declared here exactly once. Detectors call
:func:`make_finding` with a rule id, so severities, titles, remediation text and
reference ids never drift between the CLI, SARIF output and the generated docs
(``docs/RULES.md`` is produced from this file by ``scripts/gen_rules_doc.py``).
"""

from __future__ import annotations

from dataclasses import dataclass

from mcpdoctor.models import Category, Finding, Severity

P, Q, S, B = Category.PROTOCOL, Category.QUALITY, Category.SECURITY, Category.BEHAVIOR
INFO, LOW, MED, HIGH, CRIT = (
    Severity.INFO,
    Severity.LOW,
    Severity.MEDIUM,
    Severity.HIGH,
    Severity.CRITICAL,
)


@dataclass(frozen=True)
class Rule:
    id: str
    title: str
    category: Category
    severity: Severity
    why: str
    fix: str
    refs: tuple[str, ...] = ()
    dynamic: bool = False  # needs to execute tools


_RULES: list[Rule] = [
    # ------------------------------------------------------------------ protocol
    Rule("P001", "Server failed to start or initialize", P, CRIT,
         "If the server cannot complete the MCP handshake no client can use it.",
         "Run the command by hand, read stderr, and make sure stdout carries only MCP protocol messages."),
    Rule("P002", "Server crashed or hung while being tested", P, HIGH,
         "A server that dies or stops answering on unusual input lets any caller take the tool offline.",
         "Catch exceptions per tool call, return an MCP error result, and enforce timeouts on slow work.",
         ("CWE-248", "CWE-400"), True),
    Rule("P003", "Slow startup", P, LOW,
         "Clients wait for the handshake and tool listing before the first call; slow starts time out.",
         "Defer heavy initialisation until the first tool call (lazy loading)."),
    Rule("P004", "Server exposes no tools", P, LOW,
         "A tools-only scan has nothing to test. The server may only expose resources or prompts.",
         "Expose at least one tool, or ignore this finding if the server is resources/prompts only."),
    # ------------------------------------------------------------------- quality
    Rule("Q001", "Tool has no description", Q, HIGH,
         "The description is the only thing a model has to decide whether to call the tool.",
         "Add a one-to-three sentence description that says what the tool does and what it returns."),
    Rule("Q002", "Tool description too short to guide an agent", Q, MED,
         "Very short descriptions do not say what the tool does, what it returns, or when it applies.",
         "State the action, the data it works on, and what the result contains (aim for 40+ characters)."),
    Rule("Q003", "Tool description is very long", Q, LOW,
         "Long descriptions consume context on every request and bury the useful sentence.",
         "Keep descriptions under about 1,200 characters; move reference material to a resource."),
    Rule("Q004", "No guidance on when to use (or not use) the tool", Q, LOW,
         "Agents choose between tools using the descriptions; without boundaries they pick the wrong tool.",
         "Add a 'Use when...' / 'Do not use for...' sentence that separates the tool from its neighbours."),
    Rule("Q005", "Parameter has no description", Q, MED,
         "Models guess parameter meaning from the name alone, which causes invalid or wrong arguments.",
         "Add a description (with units, format and an example) to every parameter."),
    Rule("Q006", "Parameter has no type", Q, MED,
         "An untyped parameter lets the model send anything and the server cannot validate it.",
         "Declare 'type' (or 'enum' / 'anyOf') for every property in the input schema."),
    Rule("Q007", "Free-form string where a constrained format is expected", Q, LOW,
         "Paths, URLs, ids and dates accepted as unconstrained strings invite malformed and hostile input.",
         "Add 'pattern', 'format', 'enum', 'minLength'/'maxLength' to the schema and validate on the server."),
    Rule("Q008", "Two tools overlap too closely", Q, LOW,
         "Near-duplicate tools make tool selection a coin toss for the model.",
         "Merge them, or make each description say what distinguishes it from the other."),
    Rule("Q009", "Vague tool name", Q, LOW,
         "Names such as 'run' or 'tool1' say nothing about the action and collide across servers.",
         "Use a verb_noun name that describes the action (for example 'search_issues')."),
    Rule("Q010", "Inconsistent tool naming convention", Q, INFO,
         "Mixed snake_case / camelCase / kebab-case makes a tool set harder for models and humans to predict.",
         "Pick one naming convention for all tools."),
    Rule("Q011", "No behaviour annotations", Q, LOW,
         "Without readOnlyHint / destructiveHint, clients cannot ask for confirmation sensibly.",
         "Set read_only_hint and destructive_hint on every tool."),
    Rule("Q012", "Annotations contradict what the tool does", Q, HIGH,
         "A tool marked read-only whose name or description says it modifies data will skip human confirmation.",
         "Fix the annotation or the tool: read_only_hint must be false for anything that writes, sends or deletes."),
    Rule("Q013", "Too many tools", Q, LOW,
         "Model accuracy drops as the tool list grows, and every tool costs context tokens.",
         "Split into several focused servers, or expose fewer, broader tools."),
    Rule("Q014", "Tool definitions consume a large share of context", Q, LOW,
         "The full tool list is sent with every model request.",
         "Trim descriptions and schemas; drop rarely used parameters."),
    Rule("Q015", "Tool has no output schema", Q, INFO,
         "Without an output schema clients cannot validate results or let the model plan on the shape.",
         "Declare an output schema and return structured content."),
    # ------------------------------------------------------------------ security
    Rule("S001", "Instruction hijacking text in tool metadata", S, HIGH,
         "Hidden instructions in tool descriptions or schemas are read by the model as trusted guidance "
         "(tool poisoning). Typical forms: override of earlier instructions, concealment from the user, "
         "reading sensitive files, or sending data to a URL.",
         "Remove the text. Descriptions must only describe the tool's own behaviour.",
         ("OWASP-LLM01",)),
    Rule("S002", "Invisible or bidirectional control characters in metadata", S, HIGH,
         "Zero-width, bidi-override and Unicode tag characters hide instructions from human reviewers "
         "while the model still reads them.",
         "Strip the characters; reject them in a CI check.", ("OWASP-LLM01", "CWE-116")),
    Rule("S003", "Encoded payload in tool metadata", S, MED,
         "Long base64 / hex blobs in descriptions are a common way to smuggle instructions past review.",
         "Remove the blob or move legitimate binary data out of descriptions.", ("OWASP-LLM01",)),
    Rule("S004", "Tool metadata tries to steer other tools (shadowing)", S, MED,
         "A description that tells the model how to use or avoid a different tool can hijack that tool's behaviour.",
         "Describe only this tool. Never reference other tools' names with directives.", ("OWASP-LLM01",)),
    Rule("S005", "Arbitrary command or code execution surface", S, HIGH,
         "A tool that runs caller-supplied shell commands, code or raw SQL gives the model (and anyone who can "
         "inject text into its context) the full power of the server's account.",
         "Replace with narrow, parameterised tools, or run in a sandbox with explicit human approval.",
         ("CWE-78", "CWE-94", "OWASP-LLM06")),
    Rule("S006", "Credential or secret embedded in tool definitions", S, CRIT,
         "Tool metadata is sent to every connected client, so an embedded key is effectively published.",
         "Rotate the secret immediately and load credentials from the environment at call time.",
         ("CWE-798",)),
    Rule("S007", "Remote server reached over cleartext HTTP", S, HIGH,
         "Tool calls and results (which often contain credentials and private data) can be read or altered in transit.",
         "Serve over HTTPS.", ("CWE-319",)),
    Rule("S008", "Remote endpoint accepts unauthenticated requests", S, HIGH,
         "Anyone who can reach the URL can list and call every tool.",
         "Require OAuth 2.1 / bearer tokens on the MCP endpoint.", ("CWE-306",), True),
    Rule("S009", "Remote endpoint does not validate the Origin header", S, MED,
         "Without Origin validation a malicious web page can drive a local server through the browser (DNS rebinding).",
         "Reject requests whose Origin is not on an allow-list, and bind to 127.0.0.1 for local servers.",
         ("CWE-346",), True),
    Rule("S010", "Tool definitions changed since they were pinned", S, HIGH,
         "A tool whose description changes after you approved it can turn malicious later (rug pull).",
         "Review the diff. If it is legitimate, re-run 'mcpdoctor pin' and commit the new lock file.",
         ("OWASP-LLM01",)),
    # ------------------------------------------------------------------- dynamic
    Rule("D001", "Path traversal / unconfined file access", S, HIGH,
         "The tool returned the contents of files outside any sensible root when given '../' or absolute paths.",
         "Resolve the path, then require that it is inside an allowed root before opening it.",
         ("CWE-22",), True),
    Rule("D002", "Server-side request forgery (SSRF)", S, HIGH,
         "The server fetched an attacker-chosen URL pointing at the loopback interface. The same bug reaches cloud "
         "metadata endpoints and internal services.",
         "Resolve the host first and refuse loopback, link-local and private ranges (and re-check after redirects).",
         ("CWE-918",), True),
    Rule("D003", "SQL injection or raw SQL errors reach the caller", S, HIGH,
         "A quote character in a search parameter produced a database syntax error, which means the value is "
         "concatenated into the query.",
         "Use parameterised queries for every value.", ("CWE-89",), True),
    Rule("D004", "Stacked SQL statements are executed", S, MED,
         "A tool that runs 'SELECT 1; SELECT 2' will also run '...; DROP TABLE ...'.",
         "Execute exactly one statement per call and reject statements containing ';' outside literals.",
         ("CWE-89",), True),
    Rule("D005", "Read-only claim violated: a write succeeded", S, HIGH,
         "The tool is described or annotated as read-only but accepted a data-changing statement.",
         "Open the database read-only, or use a role with no write privileges.", ("CWE-89", "CWE-284"), True),
    Rule("D006", "OS command injection", S, CRIT,
         "Shell metacharacters in a parameter were executed by the server.",
         "Never pass parameters through a shell. Use argument lists (no shell=True) and validate input.",
         ("CWE-78",), True),
    Rule("D007", "Error responses leak internals", S, MED,
         "Stack traces, file-system paths and library versions in error text help attackers and bloat model context.",
         "Return a short, actionable message to the client and log the traceback server-side.",
         ("CWE-209",), True),
    Rule("D008", "Environment or secrets leaked in tool output", S, CRIT,
         "A planted canary secret placed in the server's environment appeared in a tool response.",
         "Never return os.environ or config dumps. Redact secrets and expose only whitelisted values.",
         ("CWE-200", "CWE-532"), True),
    Rule("D009", "Tool accepts input that violates its own schema", S, LOW,
         "Wrong-typed arguments were accepted, so the schema is documentation only and not enforced.",
         "Validate arguments against the input schema before running the tool.", ("CWE-20",), True),
    Rule("D010", "Unbounded response size", S, MED,
         "A large 'limit'-style argument produced an enormous response that can flood the model's context window.",
         "Cap page sizes server-side and return a continuation cursor.", ("CWE-770",), True),
    Rule("D011", "Tool definitions changed during the session", S, HIGH,
         "The tool list differed after tools were called, which is the signature of a runtime rug pull.",
         "Tool definitions must be stable for a session; announce changes via list_changed and keep them benign.",
         ("OWASP-LLM01",), True),
    # ------------------------------------------------------------------ behavior
    Rule("B001", "A schema-valid call fails (schema does not match behaviour)", B, HIGH,
         "MCPDoctor built arguments from the tool's own input schema and the call was rejected or crashed. "
         "Agents trust the schema, so they will hit the same failure.",
         "Make the schema match what the code accepts (required fields, enums, formats).",
         (), True),
    Rule("B002", "Result does not match the declared output schema", B, MED,
         "Clients that validate structured output will reject the result.",
         "Return data that conforms to the output schema, or fix the schema.", (), True),
    Rule("B003", "Slow tool", B, LOW,
         "Slow tool calls stall agent loops and trigger client timeouts.",
         "Stream progress, add pagination, or move long work to an async job.", (), True),
    Rule("B004", "Error message is not actionable", B, LOW,
         "An agent can only recover from a failure if the message says what was wrong and how to fix it.",
         "Return what was invalid and what a valid value looks like.", (), True),
    Rule("B005", "Agent selects the wrong tool for a task", B, MED,
         "In the LLM evaluation, a model given a realistic user request chose a different tool than intended.",
         "Sharpen the descriptions of the confused tools and add 'use when / do not use' guidance.", (), True),
    Rule("B006", "Agent produces invalid arguments", B, MED,
         "In the LLM evaluation, arguments chosen by the model did not validate against the input schema.",
         "Add parameter descriptions, examples, enums and formats.", (), True),
]

RULES: dict[str, Rule] = {r.id: r for r in _RULES}


def make_finding(
    rule_id: str,
    message: str,
    *,
    tool: str | None = None,
    evidence: str | None = None,
    severity: Severity | None = None,
    confidence: str = "high",
    fix: str | None = None,
) -> Finding:
    rule = RULES[rule_id]
    return Finding(
        rule_id=rule.id,
        title=rule.title,
        severity=severity or rule.severity,
        category=rule.category,
        message=message,
        tool=tool,
        evidence=(evidence[:400] if evidence else None),
        fix=fix or rule.fix,
        confidence=confidence,
    )
