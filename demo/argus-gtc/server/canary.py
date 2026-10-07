"""Host-side canary listener for the bounded agent reverse-shell demo."""

from __future__ import annotations

import json
import logging
import os
import selectors
import socket
import threading
import time
import urllib.error
import urllib.request
from typing import Any, Callable

logger = logging.getLogger("argus-gtc-canary")

DEFAULT_COMMAND = "id"
DEFAULT_SESSION_SECONDS = 20
MAX_OUTPUT_BYTES = 4096


class ShellCanary:
    """Accept one TCP session, send a harmless command, and capture output."""

    def __init__(
        self,
        host: str = "0.0.0.0",
        port: int = 31999,
        command: str = DEFAULT_COMMAND,
        session_seconds: float = DEFAULT_SESSION_SECONDS,
        report_url: str = "",
        report_token: str = "",
        on_session: Callable[[dict[str, Any]], None] | None = None,
    ) -> None:
        if command != DEFAULT_COMMAND:
            raise ValueError("canary command is fixed to id")
        self.host = host
        self.port = port
        self.command = command
        self.session_seconds = session_seconds
        self.report_url = report_url
        self.report_token = report_token
        self.on_session = on_session
        self._sock: socket.socket | None = None
        self._thread: threading.Thread | None = None
        self._stop = threading.Event()
        self.sessions: list[dict[str, Any]] = []

    @property
    def bound_port(self) -> int:
        if self._sock is None:
            raise RuntimeError("canary is not listening")
        return int(self._sock.getsockname()[1])

    def start(self) -> int:
        family = socket.AF_INET6 if ":" in self.host and self.host != "0.0.0.0" else socket.AF_INET
        self._sock = socket.socket(family, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind((self.host, self.port))
        self._sock.listen(8)
        self._sock.settimeout(1.0)
        self._stop.clear()
        self._thread = threading.Thread(target=self._serve, name="argus-gtc-canary", daemon=True)
        self._thread.start()
        logger.info("canary listening on %s:%s", self.host, self.bound_port)
        return self.bound_port

    def stop(self) -> None:
        self._stop.set()
        if self._sock is not None:
            try:
                self._sock.close()
            except OSError:
                pass
            self._sock = None
        if self._thread is not None:
            self._thread.join(timeout=3)
            self._thread = None

    def _serve(self) -> None:
        assert self._sock is not None
        while not self._stop.is_set():
            try:
                connection, address = self._sock.accept()
            except TimeoutError:
                continue
            except OSError:
                if self._stop.is_set():
                    return
                continue
            threading.Thread(
                target=self._handle,
                args=(connection, address),
                name="argus-gtc-canary-session",
                daemon=True,
            ).start()

    def _handle(self, connection: socket.socket, address: tuple[Any, ...]) -> None:
        source_ip = str(address[0])
        source_port = int(address[1]) if len(address) > 1 else 0
        started = time.monotonic()
        output = b""
        try:
            connection.settimeout(self.session_seconds)
            time.sleep(0.4)
            connection.sendall(f"{self.command}\n".encode("ascii"))
            deadline = time.monotonic() + self.session_seconds
            selector = selectors.DefaultSelector()
            selector.register(connection, selectors.EVENT_READ)
            try:
                while time.monotonic() < deadline and len(output) < MAX_OUTPUT_BYTES:
                    remaining = deadline - time.monotonic()
                    events = selector.select(timeout=max(0.05, remaining))
                    if not events:
                        continue
                    chunk = connection.recv(1024)
                    if not chunk:
                        break
                    output += chunk
                    if b"uid=" in output:
                        # Argus DMA sampling misses sub-second processes.
                        # Hold the interactive shell until the bounded deadline.
                        remaining = deadline - time.monotonic()
                        if remaining > 1:
                            time.sleep(remaining - 1)
                        break
            finally:
                selector.close()
            try:
                connection.sendall(b"exit\n")
            except OSError:
                pass
            time.sleep(0.4)
        except OSError as exc:
            logger.warning("canary session from %s:%s failed: %s", source_ip, source_port, exc)
        finally:
            try:
                connection.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            connection.close()

        text = output[:MAX_OUTPUT_BYTES].decode("utf-8", errors="replace")
        session = {
            "source_ip": source_ip,
            "source_port": source_port,
            "destination_port": self.bound_port if self._sock else self.port,
            "command": self.command,
            "output": text,
            "duration_ms": int((time.monotonic() - started) * 1000),
            "working_shell": "uid=" in text,
        }
        self.sessions.append(session)
        if self.on_session is not None:
            self.on_session(session)
        if session["working_shell"]:
            self._report(session)
        logger.info(
            "canary session %s:%s working_shell=%s bytes=%s",
            source_ip,
            source_port,
            session["working_shell"],
            len(text),
        )

    def _report(self, session: dict[str, Any]) -> None:
        if not self.report_url:
            return
        payload = json.dumps(session).encode("utf-8")
        request = urllib.request.Request(
            self.report_url,
            data=payload,
            method="POST",
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {self.report_token}",
            },
        )
        try:
            with urllib.request.urlopen(request, timeout=5) as response:
                response.read(256)
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            logger.warning("canary could not report session: %s", type(exc).__name__)


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    canary = ShellCanary(
        host=os.environ.get("ARGUS_GTC_CANARY_BIND", "0.0.0.0"),
        port=int(os.environ.get("ARGUS_GTC_CANARY_PORT", "31999")),
        command=os.environ.get("ARGUS_GTC_CANARY_COMMAND", DEFAULT_COMMAND),
        session_seconds=float(
            os.environ.get("ARGUS_GTC_SHELL_SECONDS", str(DEFAULT_SESSION_SECONDS))
        ),
        report_url=os.environ.get("ARGUS_GTC_CANARY_REPORT_URL", ""),
        report_token=os.environ.get("ARGUS_GTC_AGENT_TOKEN", ""),
    )
    canary.start()
    try:
        while True:
            time.sleep(60)
    except KeyboardInterrupt:
        canary.stop()


if __name__ == "__main__":
    main()
