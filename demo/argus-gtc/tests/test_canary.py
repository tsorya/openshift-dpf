from __future__ import annotations

import socket
import threading
import time
import unittest

from server.canary import ShellCanary


class ShellCanaryTests(unittest.TestCase):
    def test_canary_sends_id_and_records_uid_output(self):
        canary = ShellCanary(host="127.0.0.1", port=0, session_seconds=3)
        port = canary.start()
        self.addCleanup(canary.stop)

        def pretend_shell() -> None:
            with socket.create_connection(("127.0.0.1", port), timeout=3) as client:
                client.settimeout(3)
                command = client.recv(64)
                self.assertIn(b"id", command)
                client.sendall(b"uid=1000(demo) gid=1000(demo)\n")
                try:
                    client.recv(16)
                except OSError:
                    pass

        worker = threading.Thread(target=pretend_shell)
        worker.start()
        worker.join(timeout=5)
        self.assertFalse(worker.is_alive())
        deadline = time.monotonic() + 2
        while not canary.sessions and time.monotonic() < deadline:
            time.sleep(0.05)
        self.assertEqual(len(canary.sessions), 1)
        session = canary.sessions[0]
        self.assertEqual(session["command"], "id")
        self.assertTrue(session["working_shell"])
        self.assertIn("uid=1000(demo)", session["output"])
        self.assertEqual(session["destination_port"], port)

    def test_canary_rejects_non_id_command(self):
        with self.assertRaisesRegex(ValueError, "fixed to id"):
            ShellCanary(command="uname")


if __name__ == "__main__":
    unittest.main()
