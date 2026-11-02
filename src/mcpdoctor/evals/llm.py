"""A dependency-free client for any OpenAI-compatible chat-completions endpoint.

Works with Google Gemini (OpenAI compatibility layer), Groq, OpenRouter, a local Ollama server, OpenAI itself
and anything else that speaks the same protocol. Keys are read from environment variables and are never printed
or written to reports.
"""

from __future__ import annotations

import json
import os
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Any

# Defaults reflect provider documentation as of late 2026. Model names change often: always override with --model
# if a default stops working.
PRESETS: dict[str, dict[str, str | None]] = {
    "gemini": {"base_url": "https://generativelanguage.googleapis.com/v1beta/openai/",
               "key_env": "GEMINI_API_KEY", "model": "gemini-2.5-flash"},
    "groq": {"base_url": "https://api.groq.com/openai/v1", "key_env": "GROQ_API_KEY",
             "model": "openai/gpt-oss-120b"},
    "openrouter": {"base_url": "https://openrouter.ai/api/v1", "key_env": "OPENROUTER_API_KEY",
                   "model": "google/gemma-4-31b-it:free"},
    "ollama": {"base_url": "http://localhost:11434/v1", "key_env": None, "model": "qwen3:8b"},
    "openai": {"base_url": "https://api.openai.com/v1", "key_env": "OPENAI_API_KEY", "model": "gpt-4o-mini"},
}


class LlmError(RuntimeError):
    pass


@dataclass
class LlmConfig:
    provider: str
    base_url: str
    model: str
    api_key: str | None = None
    timeout: float = 90.0
    rpm: int = 15  # stay inside typical free-tier request-per-minute limits

    @staticmethod
    def resolve(provider: str, model: str | None = None, base_url: str | None = None,
                key_env: str | None = None, rpm: int | None = None) -> LlmConfig:
        preset = PRESETS.get(provider)
        if preset is None and not base_url:
            raise LlmError(f"unknown provider {provider!r}; choose one of {', '.join(PRESETS)} "
                           "or pass --llm-base-url for a custom OpenAI-compatible endpoint")
        preset = preset or {}
        url = base_url or str(preset.get("base_url"))
        env_name = key_env or preset.get("key_env")
        key = os.environ.get(env_name) if env_name else None
        if env_name and not key:
            raise LlmError(f"environment variable {env_name} is not set (needed for provider '{provider}')")
        return LlmConfig(provider=provider, base_url=url.rstrip("/"),
                         model=model or str(preset.get("model") or ""), api_key=key,
                         rpm=rpm or 15)


class ChatClient:
    def __init__(self, cfg: LlmConfig) -> None:
        self.cfg = cfg
        self.requests = 0
        self.prompt_tokens = 0
        self.completion_tokens = 0
        self._last_call = 0.0

    def _throttle(self) -> None:
        gap = 60.0 / max(1, self.cfg.rpm)
        wait = self._last_call + gap - time.monotonic()
        if wait > 0:
            time.sleep(wait)
        self._last_call = time.monotonic()

    def chat(self, messages: list[dict[str, Any]], tools: list[dict[str, Any]] | None = None,
             max_tokens: int = 700) -> dict[str, Any]:
        body: dict[str, Any] = {"model": self.cfg.model, "messages": messages, "temperature": 0,
                                "max_tokens": max_tokens}
        if tools:
            body["tools"] = tools
            body["tool_choice"] = "auto"
        headers = {"Content-Type": "application/json", "Accept": "application/json",
                   "User-Agent": "mcpdoctor"}
        if self.cfg.api_key:
            headers["Authorization"] = f"Bearer {self.cfg.api_key}"
        req_bytes = json.dumps(body).encode()
        url = f"{self.cfg.base_url}/chat/completions"

        delay = 2.0
        for attempt in range(5):
            self._throttle()
            req = urllib.request.Request(url, data=req_bytes, headers=headers, method="POST")
            try:
                with urllib.request.urlopen(req, timeout=self.cfg.timeout) as resp:
                    data = json.loads(resp.read().decode("utf-8", "replace"))
                break
            except urllib.error.HTTPError as exc:
                text = exc.read(600).decode("utf-8", "replace")
                if exc.code in (429, 500, 502, 503, 504) and attempt < 4:
                    retry_after = exc.headers.get("Retry-After") if exc.headers else None
                    try:
                        wait = min(60.0, float(retry_after)) if retry_after else delay
                    except ValueError:
                        wait = delay
                    time.sleep(wait)
                    delay = min(30.0, delay * 2)
                    continue
                raise LlmError(f"{self.cfg.provider} returned HTTP {exc.code}: {_scrub(text, self.cfg.api_key)}") from exc
            except (urllib.error.URLError, TimeoutError, OSError) as exc:
                if attempt < 2:
                    time.sleep(delay)
                    delay *= 2
                    continue
                raise LlmError(f"could not reach {self.cfg.base_url}: {exc}") from exc
        else:
            raise LlmError("gave up after repeated rate-limit / server errors")

        self.requests += 1
        usage = data.get("usage") or {}
        self.prompt_tokens += int(usage.get("prompt_tokens") or 0)
        self.completion_tokens += int(usage.get("completion_tokens") or 0)
        try:
            return dict(data["choices"][0]["message"])
        except (KeyError, IndexError, TypeError) as exc:
            raise LlmError(f"unexpected response shape from {self.cfg.provider}: {str(data)[:200]}") from exc


def _scrub(text: str, secret: str | None) -> str:
    out = text.replace("\n", " ")
    if secret:
        out = out.replace(secret, "***")
    return out[:300]
