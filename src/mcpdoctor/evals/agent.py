"""LLM-driven evaluation: can a model pick the right tool and call it correctly from the descriptions alone?

Method
------
1. For every tool, a model writes realistic user requests that need *that* tool, without naming it
   (tasks are cached in a file so the benchmark stays fixed between runs and across code changes).
2. A second, independent call gives the model *all* tools and one request, and asks it to answer with one tool
   call.
3. Scoring is deterministic: did it choose the intended tool, do the arguments validate against the tool's input
   schema, and (optionally) does the call succeed against the real server?
"""

from __future__ import annotations

import asyncio
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import jsonschema

from mcpdoctor.evals.llm import ChatClient, LlmError
from mcpdoctor.models import ToolInfo
from mcpdoctor.probes import ProbeContext, tool_is_probe_safe
from mcpdoctor.rules import make_finding

TASKS_SCHEMA = "mcpdoctor.tasks/1"

_TASKGEN_SYSTEM = (
    "You write test requests for evaluating AI agents that use tools. Reply with JSON only."
)
_AGENT_SYSTEM = (
    "You are an assistant connected to tools. For the user's request, answer with exactly one tool call that "
    "best fulfils it. Do not explain."
)


@dataclass
class Task:
    tool: str
    request: str


def _clean_schema(schema: Any) -> Any:
    if isinstance(schema, dict):
        return {k: _clean_schema(v) for k, v in schema.items() if k not in ("$schema", "title")}
    if isinstance(schema, list):
        return [_clean_schema(v) for v in schema]
    return schema


def _api_name(name: str, used: set[str]) -> str:
    safe = re.sub(r"[^A-Za-z0-9_-]", "_", name)[:64] or "tool"
    base, i = safe, 1
    while safe in used:
        i += 1
        safe = f"{base[:60]}_{i}"
    used.add(safe)
    return safe


def tools_payload(tools: list[ToolInfo]) -> tuple[list[dict[str, Any]], dict[str, str]]:
    used: set[str] = set()
    payload, mapping = [], {}
    for t in tools:
        api = _api_name(t.name, used)
        mapping[api] = t.name
        payload.append({"type": "function", "function": {
            "name": api, "description": t.description or "",
            "parameters": _clean_schema(t.input_schema) or {"type": "object", "properties": {}}}})
    return payload, mapping


def _extract_json(text: str) -> Any:
    text = (text or "").strip()
    text = re.sub(r"^```(?:json)?|```$", "", text, flags=re.M).strip()
    start, end = text.find("{"), text.rfind("}")
    if start == -1 or end == -1:
        raise ValueError("no JSON object in model reply")
    return json.loads(text[start:end + 1])


def _fingerprints(tools: list[ToolInfo]) -> dict[str, str]:
    return {t.name: t.fingerprint() for t in tools}


def load_cached_tasks(path: Path, tools: list[ToolInfo]) -> list[Task] | None:
    try:
        data = json.loads(path.read_text())
    except (OSError, json.JSONDecodeError):
        return None
    if data.get("schema") != TASKS_SCHEMA or data.get("fingerprints") != _fingerprints(tools):
        return None
    return [Task(**t) for t in data.get("tasks", [])]


def save_tasks(path: Path, tools: list[ToolInfo], tasks: list[Task], model: str) -> None:
    path.write_text(json.dumps({
        "schema": TASKS_SCHEMA, "generated_by": model, "fingerprints": _fingerprints(tools),
        "tasks": [{"tool": t.tool, "request": t.request} for t in tasks]}, indent=2) + "\n")


async def generate_tasks(client: ChatClient, tools: list[ToolInfo], per_tool: int) -> list[Task]:
    tasks: list[Task] = []
    for t in tools:
        others = ", ".join(o.name for o in tools if o.name != t.name)[:400] or "(none)"
        prompt = (
            f"Tool under test:\n  name: {t.name}\n  description: {t.description}\n"
            f"  parameters: {json.dumps(_clean_schema(t.input_schema))[:1200]}\n"
            f"Other tools in the same server (for contrast): {others}\n\n"
            f"Write {per_tool} different, realistic requests a person might type to an assistant that can only be "
            "fulfilled by THIS tool. Rules: never mention the tool name or parameter names; include concrete example "
            "values (ids, names, numbers) inside the request; keep each under 30 words.\n"
            'Return JSON: {"requests": ["...", "..."]}')
        try:
            msg = await asyncio.to_thread(client.chat, [
                {"role": "system", "content": _TASKGEN_SYSTEM}, {"role": "user", "content": prompt}], None, 500)
            reqs = _extract_json(msg.get("content") or "").get("requests", [])
        except (LlmError, ValueError, json.JSONDecodeError):
            reqs = []
        for r in reqs[:per_tool]:
            if isinstance(r, str) and r.strip():
                tasks.append(Task(tool=t.name, request=r.strip()))
    return tasks


async def run_agent_eval(ctx: ProbeContext, client: ChatClient, tasks: list[Task], execute: bool) -> dict[str, Any]:
    tools = ctx.tools
    by_name = {t.name: t for t in tools}
    payload, mapping = tools_payload(tools)
    results: list[dict[str, Any]] = []
    consecutive_errors = 0
    aborted: str | None = None

    for task in tasks:
        row: dict[str, Any] = {"expected": task.tool, "request": task.request, "chosen": None,
                               "correct": False, "args_valid": None, "executed": None}
        try:
            msg = await asyncio.to_thread(client.chat, [
                {"role": "system", "content": _AGENT_SYSTEM}, {"role": "user", "content": task.request}], payload, 400)
            consecutive_errors = 0
        except LlmError as exc:
            consecutive_errors += 1
            row["error"] = str(exc)[:200]
            results.append(row)
            if consecutive_errors >= 3:
                aborted = str(exc)[:200]
                break
            continue

        calls = msg.get("tool_calls") or []
        if not calls:
            row["chosen"] = None
            results.append(row)
            continue
        fn = calls[0].get("function", {})
        chosen = mapping.get(fn.get("name", ""), fn.get("name"))
        row["chosen"] = chosen
        row["correct"] = chosen == task.tool
        try:
            args = json.loads(fn.get("arguments") or "{}")
            if not isinstance(args, dict):
                raise ValueError("arguments are not an object")
        except (ValueError, json.JSONDecodeError) as exc:
            row["args_valid"] = False
            row["args_error"] = f"arguments are not valid JSON: {exc}"
            results.append(row)
            continue
        target_tool = by_name.get(chosen or "")
        if target_tool is not None:
            try:
                jsonschema.validate(args, _clean_schema(target_tool.input_schema))
                row["args_valid"] = True
            except jsonschema.ValidationError as exc:
                row["args_valid"] = False
                row["args_error"] = exc.message[:200]
            except jsonschema.SchemaError:
                row["args_valid"] = None
            if execute and row["args_valid"] and (ctx.config.probe_all or tool_is_probe_safe(target_tool)[0]):
                rec = await ctx.call(target_tool.name, args, "agent")
                row["executed"] = rec.succeeded
        results.append(row)

    return _summarise(ctx, client, results, aborted)


def _summarise(ctx: ProbeContext, client: ChatClient, results: list[dict[str, Any]], aborted: str | None) -> dict[str, Any]:
    answered = [r for r in results if "error" not in r]
    correct = [r for r in answered if r["correct"]]
    validated = [r for r in answered if r["args_valid"] is not None]
    valid = [r for r in validated if r["args_valid"]]
    executed = [r for r in answered if r["executed"] is not None]
    confusions: dict[tuple[str, str], int] = {}
    per_tool: dict[str, dict[str, int]] = {}
    for r in answered:
        pt = per_tool.setdefault(r["expected"], {"tasks": 0, "correct": 0, "invalid_args": 0})
        pt["tasks"] += 1
        pt["correct"] += int(r["correct"])
        if r["args_valid"] is False:
            pt["invalid_args"] += 1
        if not r["correct"]:
            key = (r["expected"], r["chosen"] or "(no tool call)")
            confusions[key] = confusions.get(key, 0) + 1

    for tool, pt in per_tool.items():
        misses = [(c, n) for (e, c), n in confusions.items() if e == tool]
        if misses:
            detail = ", ".join(f"'{c}' x{n}" for c, n in misses)
            ctx.add(make_finding(
                "B005", f"{pt['tasks'] - pt['correct']} of {pt['tasks']} requests meant for '{tool}' went to: {detail}.",
                tool=tool, confidence="medium"))
        if pt["invalid_args"]:
            example = next((r for r in answered if r["expected"] == tool and r["args_valid"] is False), {})
            ctx.add(make_finding(
                "B006", f"{pt['invalid_args']} of {pt['tasks']} calls for '{tool}' had arguments that fail the schema: "
                f"{example.get('args_error', '')}.", tool=tool, confidence="medium"))

    n = len(answered)
    summary = {
        "provider": client.cfg.provider, "model": client.cfg.model, "tasks": len(results), "answered": n,
        "tool_selection_accuracy": round(len(correct) / n, 3) if n else None,
        "argument_validity": round(len(valid) / len(validated), 3) if validated else None,
        "execution_success": round(sum(1 for r in executed if r["executed"]) / len(executed), 3) if executed else None,
        "requests": client.requests, "prompt_tokens": client.prompt_tokens,
        "completion_tokens": client.completion_tokens,
        "avg_prompt_tokens_per_request": round(client.prompt_tokens / client.requests) if client.requests else None,
        "confusions": [{"expected": e, "chosen": c, "count": k} for (e, c), k in sorted(confusions.items())],
        "per_tool": per_tool, "errors": len(results) - n, "aborted": aborted,
    }
    return summary
