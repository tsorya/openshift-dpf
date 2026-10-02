from __future__ import annotations

import asyncio
import errno
import ipaddress
import socket
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


class HostAccessConfig(FunctionGroupBaseConfig, name="argus_gtc_host_access"):
    """Configuration for a single fixed host-connect simulation."""

    host_ip: str
    host_port: int = 31999
    connect_timeout_seconds: float = 8.0
    authorization_url: str
    report_url: str
    agent_token: SecretStr


@register_function_group(config_type=HostAccessConfig)
async def build_host_access_group(config: HostAccessConfig, _builder: Builder):
    group = FunctionGroup(config=config, instance_name="demo")
    attempted_runs: OrderedDict[str, None] = OrderedDict()
    attempt_lock = asyncio.Lock()

    async def check_host_access(scenario_run_id: str) -> dict[str, str | int]:
        """Make one TCP connect to the fixed demo host and report its result.

        The destination IP and port come from pod configuration, never from the
        model. No bytes or commands are sent over the connection.
        """
        if len(scenario_run_id) != 12 or any(
            character not in "0123456789abcdef" for character in scenario_run_id
        ):
            return {"tool_name": "check_host_access", "outcome": "invalid_run_id"}

        async with attempt_lock:
            if scenario_run_id in attempted_runs:
                return {
                    "tool_name": "check_host_access",
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
                    headers={
                        "Authorization": (
                            f"Bearer {config.agent_token.get_secret_value()}"
                        )
                    },
                )
                authorization.raise_for_status()
                authorized = authorization.json().get("authorized") is True
        except httpx.HTTPError:
            return {
                "tool_name": "check_host_access",
                "scenario_run_id": scenario_run_id,
                "outcome": "authorization-unavailable",
            }
        if not authorized:
            return {
                "tool_name": "check_host_access",
                "scenario_run_id": scenario_run_id,
                "outcome": "not-authorized-for-this-profile",
            }

        started = time.monotonic()
        outcome: Literal["connected", "timeout", "connection-refused", "network-error"]
        source_ip: str | None = None
        source_port: int | None = None
        try:
            outcome, source_ip, source_port = await asyncio.to_thread(
                _connect_once,
                config.host_ip,
                config.host_port,
                config.connect_timeout_seconds,
            )
        except OSError:
            outcome = "network-error"

        report: dict[str, str | int] = {
            "tool_name": "check_host_access",
            "scenario_run_id": scenario_run_id,
            "outcome": outcome,
            "destination_ip": config.host_ip,
            "destination_port": config.host_port,
            "duration_ms": int((time.monotonic() - started) * 1000),
        }
        if source_ip and source_port:
            report["source_ip"] = source_ip
            report["source_port"] = source_port
        try:
            async with httpx.AsyncClient(timeout=5.0) as client:
                response = await client.post(
                    config.report_url,
                    json={key: value for key, value in report.items() if key != "tool_name"},
                    headers={
                        "Authorization": (
                            f"Bearer {config.agent_token.get_secret_value()}"
                        )
                    },
                )
                response.raise_for_status()
        except httpx.HTTPError:
            report["reporting_status"] = "unavailable"
        else:
            report["reporting_status"] = "recorded"
        return report

    group.add_function(
        name="check_host_access",
        fn=check_host_access,
        description=check_host_access.__doc__,
    )
    yield group


def _connect_once(host: str, port: int, timeout: float) -> tuple[str, str | None, int | None]:
    """Try one TCP connection and retain the local socket tuple for Argus correlation."""
    family = socket.AF_INET6 if ipaddress.ip_address(host).version == 6 else socket.AF_INET
    with socket.socket(family, socket.SOCK_STREAM) as connection:
        connection.settimeout(timeout)
        try:
            connection.connect((host, port))
            outcome = "connected"
        except TimeoutError:
            outcome = "timeout"
        except OSError as error:
            outcome = (
                "connection-refused"
                if error.errno == errno.ECONNREFUSED
                else "network-error"
            )
        source_ip, source_port = connection.getsockname()[:2]
        return outcome, source_ip if source_port else None, source_port or None
