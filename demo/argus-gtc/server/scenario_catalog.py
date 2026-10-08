"""Presenter descriptions for the allowlisted workload scenarios.

The UI receives this catalog from GET /api/scenarios. The runbook points here so
the action description has one source of truth.
"""

SCENARIO_CATALOG = {
    "discovery": {
        "label": "Discovery",
        "what": "Checks the operating system, current user, and running processes, then reads files planted for the demo.",
        "why": "Shows exploration activity and establishes ordinary visibility inside the workload.",
        "watch": "INFO process and file-access events from these commands. A HIGH alert is not expected simply because discovery ran.",
        "duration": "Short action; process and file records may arrive later.",
    },
    "exec-memory": {
        "label": "Executable memory",
        "what": "A Python process creates executable memory, writes inert bytes into it, and holds it for 45 seconds. It never executes those bytes.",
        "why": "Shows visibility into a memory condition associated with suspicious code loading.",
        "watch": "Native WARNING EVENT ‘New Executable Anonymous Memory Mapped’ for this workload and run. A process-start record alone is insufficient.",
        "duration": "About 45 seconds, plus up to 15 seconds for native evidence.",
    },
    "reverse-shell": {
        "label": "Reverse shell",
        "what": "Opens a command shell inside the VM and connects its input and output to the controlled demo server for up to 20 seconds.",
        "why": "Shows the remote-command channel pattern associated with control of a compromised workload.",
        "watch": "Related process and network events. Native detection requires a matching ‘Reverse Shell Detected’ ALERT/HIGH; running the action does not guarantee it.",
        "duration": "Up to 20 seconds, plus up to 45 seconds for a native alert.",
    },
    "audit-evasion": {
        "label": "Audit evasion",
        "what": "Starts an interactive demo shell, establishes a harmless history baseline, clears it, and disables further history recording in that temporary session.",
        "why": "Models an attempt to hide commands from shell history while the external observer keeps monitoring.",
        "watch": "Native ALERT/HIGH ‘Shell History Cleared’ or ‘Shell History Disabled’. Ordinary process events do not prove evasion detection.",
        "duration": "About 38 seconds, plus up to 45 seconds for a native alert.",
    },
}
