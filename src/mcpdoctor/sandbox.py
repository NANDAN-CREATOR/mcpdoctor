"""Run the server under test inside a locked-down Docker container.

Why: MCPDoctor executes third-party code and then feeds it hostile input. Inside the sandbox the server has no
network, a read-only root file system, no Linux capabilities, a non-root user and hard CPU / memory / process
limits, so even a server that is actively malicious cannot reach your files, your network or your credentials.

The container is started with ``docker run -i`` and spoken to over stdio exactly like a local process.
"""

from __future__ import annotations

import secrets
import shutil
import subprocess
from dataclasses import dataclass, field

from mcpdoctor.target import Isolation, Target, TargetError

CONTAINER_HOME = "/home/probe"
CONTAINER_WORK = "/work"
CANARY_IN_CONTAINER = f"{CONTAINER_HOME}/mcpdoctor_canary.txt"


@dataclass
class SandboxConfig:
    image: str
    mounts: list[str] = field(default_factory=list)  # "host_path:container_path[:ro|rw]"
    memory: str = "512m"
    cpus: str = "1"
    pids_limit: int = 256
    network: str = "none"  # "none" (default) or "bridge"
    name: str = field(default_factory=lambda: f"mcpdoctor-{secrets.token_hex(4)}")


def docker_available() -> tuple[bool, str]:
    if shutil.which("docker") is None:
        return False, "the 'docker' command was not found on PATH"
    try:
        proc = subprocess.run(["docker", "info", "--format", "{{.ServerVersion}}"],
                              capture_output=True, text=True, timeout=15)
    except (OSError, subprocess.TimeoutExpired) as exc:
        return False, f"could not talk to docker: {exc}"
    if proc.returncode != 0:
        return False, (proc.stderr.strip().splitlines() or ["docker daemon is not reachable"])[-1]
    return True, proc.stdout.strip()


def _validate_mount(spec: str) -> str:
    parts = spec.split(":")
    if len(parts) not in (2, 3) or not parts[0] or not parts[1].startswith("/"):
        raise TargetError(f"--mount must look like /host/path:/container/path[:ro], got {spec!r}")
    if len(parts) == 2:
        return f"{spec}:ro"  # read-only unless the caller explicitly says rw
    if parts[2] not in ("ro", "rw"):
        raise TargetError(f"mount mode must be ro or rw, got {parts[2]!r} in {spec!r}")
    return spec


def build_docker_command(cfg: SandboxConfig, command: list[str], iso: Isolation,
                         extra_env: dict[str, str] | None = None) -> list[str]:
    """Return the full ``docker run`` argv. Pure function, covered by unit tests."""
    if not command:
        raise TargetError("sandbox needs a command to run inside the image")
    if cfg.network not in ("none", "bridge"):
        raise TargetError("sandbox network must be 'none' or 'bridge'")
    argv = [
        "docker", "run", "--rm", "-i", "--init", "--name", cfg.name,
        "--network", cfg.network,
        "--read-only",
        "--tmpfs", "/tmp:rw,noexec,nosuid,size=64m",
        "--cap-drop", "ALL",
        "--security-opt", "no-new-privileges",
        "--pids-limit", str(cfg.pids_limit),
        "--memory", cfg.memory,
        "--cpus", cfg.cpus,
        "--user", "65534:65534",
        "-v", f"{iso.home}:{CONTAINER_HOME}:ro",
        "-v", f"{iso.workdir}:{CONTAINER_WORK}:ro",
        "-w", CONTAINER_WORK,
        "-e", f"HOME={CONTAINER_HOME}",
        "-e", "PYTHONDONTWRITEBYTECODE=1",
        "-e", "npm_config_cache=/tmp/.npm",
    ]
    env = {**iso.env_tokens, **(extra_env or {})}
    for key, value in env.items():
        argv += ["-e", f"{key}={value}"]
    for mount in cfg.mounts:
        argv += ["-v", _validate_mount(mount)]
    argv.append(cfg.image)
    argv += command
    return argv


def sandbox_target(target: Target, cfg: SandboxConfig, iso: Isolation) -> Target:
    """Wrap a stdio target so that it runs inside the container."""
    if target.kind != "stdio":
        raise TargetError("--sandbox only applies to local (stdio) servers; remote URLs are not run by MCPDoctor")
    iso.server_canary_path = CANARY_IN_CONTAINER
    argv = build_docker_command(cfg, target.command, iso, target.env)
    return Target(kind="stdio", label=target.label, command=argv, env={}, cwd=None, sandboxed=True)


def force_remove(name: str) -> None:
    """Belt and braces: make sure the container is gone even if the client died."""
    if shutil.which("docker"):
        subprocess.run(["docker", "rm", "-f", name], capture_output=True, timeout=30, check=False)
