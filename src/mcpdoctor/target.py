"""Describing *what* is being tested, and the isolated environment it runs in."""

from __future__ import annotations

import json
import os
import secrets
import shutil
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import urlparse


class TargetError(ValueError):
    """The user asked for a target we cannot build."""


@dataclass
class Target:
    kind: str  # "stdio" | "http"
    label: str
    command: list[str] = field(default_factory=list)
    url: str | None = None
    env: dict[str, str] = field(default_factory=dict)
    cwd: str | None = None
    headers: dict[str, str] = field(default_factory=dict)
    sandboxed: bool = False  # command is a `docker run ...` line; env/cwd are already encoded in it

    @property
    def is_remote(self) -> bool:
        if self.kind != "http" or not self.url:
            return False
        host = (urlparse(self.url).hostname or "").lower()
        return host not in ("localhost", "127.0.0.1", "::1", "0.0.0.0")  # noqa: S104

    @staticmethod
    def from_command(command: list[str], *, label: str | None = None, env: dict[str, str] | None = None,
                     cwd: str | None = None) -> Target:
        if not command:
            raise TargetError("no server command given (example: mcpdoctor scan -- python server.py)")
        return Target(kind="stdio", label=label or " ".join(command), command=_absolutize(command),
                      env=dict(env or {}), cwd=cwd)

    @staticmethod
    def from_url(url: str, *, headers: dict[str, str] | None = None, label: str | None = None) -> Target:
        parsed = urlparse(url)
        if parsed.scheme not in ("http", "https") or not parsed.netloc:
            raise TargetError(f"not a valid http(s) URL: {url!r}")
        return Target(kind="http", label=label or url, url=url, headers=dict(headers or {}))


def _absolutize(command: list[str]) -> list[str]:
    """Make file arguments absolute because the server is started from a different working directory."""
    out = []
    for i, part in enumerate(command):
        if (i == 0 or not part.startswith("-")) and os.path.exists(part) and not os.path.isabs(part):
            out.append(os.path.abspath(part))
        else:
            out.append(part)
    return out


def load_config_targets(path: str | Path, only: str | None = None) -> list[Target]:
    """Read a Claude Desktop / Cursor / VS Code style MCP config file."""
    p = Path(path).expanduser()
    try:
        data = json.loads(p.read_text())
    except FileNotFoundError as exc:
        raise TargetError(f"config file not found: {p}") from exc
    except json.JSONDecodeError as exc:
        raise TargetError(f"config file is not valid JSON: {p} ({exc})") from exc
    servers = data.get("mcpServers") or data.get("servers") or {}
    if not isinstance(servers, dict) or not servers:
        raise TargetError(f"no 'mcpServers' (or 'servers') section found in {p}")
    targets: list[Target] = []
    for name, spec in servers.items():
        if only and name != only:
            continue
        if not isinstance(spec, dict):
            continue
        if spec.get("url"):
            targets.append(Target.from_url(spec["url"], headers=spec.get("headers") or {}, label=name))
        elif spec.get("command"):
            cmd = [str(spec["command"]), *[str(a) for a in spec.get("args", [])]]
            targets.append(Target(kind="stdio", label=name, command=_absolutize(cmd),
                                  env={k: str(v) for k, v in (spec.get("env") or {}).items()},
                                  cwd=spec.get("cwd")))
    if only and not targets:
        raise TargetError(f"server {only!r} not found in {p}; available: {', '.join(servers)}")
    return targets


@dataclass
class Isolation:
    """A throw-away home directory and working directory seeded with *canaries*.

    Canaries are unique fake secrets. If one ever shows up in a tool's output, the tool read data it
    should not have been able to reach (a file outside its root, or the process environment).
    """

    root: Path
    home: Path
    workdir: Path
    file_canary_path: Path
    file_token: str
    env_tokens: dict[str, str]
    env: dict[str, str]
    server_canary_path: str = ""  # the canary file's path as the *server* sees it (differs inside Docker)

    @staticmethod
    def create(extra_env: dict[str, str] | None = None) -> Isolation:
        root = Path(tempfile.mkdtemp(prefix="mcpdoctor-"))
        home = root / "home"
        workdir = root / "work"
        (home / ".aws").mkdir(parents=True)
        workdir.mkdir()
        file_token = f"mcpdoctor-canary-{secrets.token_hex(8)}"
        canary = home / "mcpdoctor_canary.txt"
        canary.write_text(f"{file_token}\n")
        env_tokens = {
            "MCPDOCTOR_CANARY_SECRET": f"mcpdoctor-canary-{secrets.token_hex(8)}",
            "AWS_SECRET_ACCESS_KEY": f"mcpdoctor-canary-{secrets.token_hex(8)}",
            "GITHUB_TOKEN": f"mcpdoctor-canary-{secrets.token_hex(8)}",
            "API_KEY": f"mcpdoctor-canary-{secrets.token_hex(8)}",
        }
        (home / ".aws" / "credentials").write_text(
            f"[default]\naws_secret_access_key = mcpdoctor-canary-{secrets.token_hex(8)}\n"
        )
        (workdir / "allowed.txt").write_text("hello from the allowed working directory\n")
        env = {"HOME": str(home), "USERPROFILE": str(home), **env_tokens, **(extra_env or {})}
        return Isolation(root=root, home=home, workdir=workdir, file_canary_path=canary,
                         file_token=file_token, env_tokens=env_tokens, env=env,
                         server_canary_path=str(canary))

    def cleanup(self) -> None:
        shutil.rmtree(self.root, ignore_errors=True)

    def all_env_tokens(self) -> list[str]:
        return list(self.env_tokens.values())


def parse_kv(pairs: tuple[str, ...] | list[str], what: str) -> dict[str, str]:
    out: dict[str, Any] = {}
    for item in pairs:
        if "=" not in item:
            raise TargetError(f"{what} must look like KEY=VALUE, got {item!r}")
        k, v = item.split("=", 1)
        out[k.strip()] = v
    return out
