"""Presenter descriptions for the allowlisted workload scenarios.

The UI receives this catalog from GET /api/scenarios. The runbook points here so
the action description has one source of truth.
"""

SCENARIO_CATALOG = {
    "discovery": {
        "label": "Discovery",
        "primary": True,
        "what": "Checks the operating system, current user, and running processes, then reads files planted for the demo.",
        "why": "Shows exploration activity and establishes ordinary visibility inside the workload.",
        "watch": "INFO process and file-access events from these commands. A HIGH alert is not expected simply because discovery ran.",
        "duration": "Short action; process and file records may arrive later.",
    },
    "exec-memory": {
        "label": "Executable memory",
        "primary": True,
        "what": "A Python process creates executable memory, writes inert bytes into it, and holds it for 45 seconds. It never executes those bytes.",
        "why": "Shows visibility into a memory condition associated with suspicious code loading.",
        "watch": "Native WARNING EVENT ‘New Executable Anonymous Memory Mapped’ for this workload and run. A process-start record alone is insufficient.",
        "duration": "About 45 seconds, plus up to 15 seconds for native evidence.",
    },
    "reverse-shell": {
        "label": "Reverse shell",
        "primary": True,
        "what": "Opens a command shell inside the VM and connects its input and output to the controlled demo server for up to 20 seconds.",
        "why": "Shows the remote-command channel pattern associated with control of a compromised workload.",
        "watch": "Related process and network events. Native detection requires a matching ‘Reverse Shell Detected’ ALERT/HIGH; running the action does not guarantee it.",
        "duration": "Up to 20 seconds, plus up to 45 seconds for a native alert.",
    },
    "audit-evasion": {
        "label": "Audit evasion",
        "primary": True,
        "what": "Starts an interactive demo shell, establishes a harmless history baseline, clears it, and disables further history recording in that temporary session.",
        "why": "Models an attempt to hide commands from shell history while the external observer keeps monitoring.",
        "watch": "Native ALERT/HIGH ‘Shell History Cleared’ or ‘Shell History Disabled’. Ordinary process events do not prove evasion detection.",
        "duration": "About 38 seconds, plus up to 45 seconds for a native alert.",
    },
    "phone-home": {
        "label": "Phone home",
        "primary": False,
        "what": "Opens a connection to the controlled demo server, sends the run identifier, and holds it for 20 seconds. Shell input and output are not attached.",
        "why": "Connects outgoing network activity with the process and VM that created it.",
        "watch": "Native INFO EVENT ‘Network Connection Created’ with the matching demo destination. This is not a reverse-shell alert.",
        "duration": "About 20 seconds, plus up to 15 seconds for native evidence.",
    },
    "shell-history": {
        "label": "Legacy shell-history test",
        "primary": False,
        "what": "Runs the original non-interactive script that disables history, redirects its history file, and attempts to clear it.",
        "why": "Keeps the older telemetry example; interactive Audit evasion is the preferred history-alert demonstration.",
        "watch": "Process telemetry for the run. A scenario label or successful script is not native-alert proof.",
        "duration": "Short action; process records may arrive later.",
    },
    "decoy-modify": {
        "label": "Modify a demo file",
        "primary": False,
        "what": "Appends a demo marker to a planted credentials file and reads it back. The file contains demonstration data.",
        "why": "Shows processes interacting with files inside the VM.",
        "watch": "File-access and process events for the planted file. File access alone does not prove Argus detected a content change.",
        "duration": "Short action; file records may arrive later.",
    },
    "network-burst": {
        "label": "Network burst",
        "primary": False,
        "what": "Sends 5 MiB of zero-filled test data to the controlled demo server.",
        "why": "Shows a bounded transfer and its sending processes and network activity.",
        "watch": "Process and network records. Show a traffic-volume alert only if Argus actually emits one.",
        "duration": "Short bounded transfer; network records may arrive later.",
    },
    "compute-simulation": {
        "label": "Compute activity",
        "primary": False,
        "what": "Calculates 5,000 integer squares and discards the results, without contacting another server or changing the demo files.",
        "why": "Shows monitoring during benign activity when no attack is simulated.",
        "watch": "INFO process lifecycle records may be sparse. No native security alert is expected.",
        "duration": "Short action; process records may arrive later.",
    },
}
