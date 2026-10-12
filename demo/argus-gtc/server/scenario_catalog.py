"""Presenter descriptions for the allowlisted workload scenarios.

The UI receives this catalog from GET /api/scenarios. The runbook points here so
the action description has one source of truth.
"""

EXEC_MEMORY_HOLD_SECONDS = 15

SCENARIO_CATALOG = {
    "discovery": {
        "label": "Discovery",
        "what": "Checks the operating system, current user, and running processes, then reads files planted for the demo.",
        "why": "Shows exploration activity and establishes ordinary visibility inside the workload.",
        "watch": "INFO process and file-access events from these commands. A HIGH alert is not expected simply because discovery ran.",
        "steps": [
            "Read the VM's system and user identity with uname -a and id.",
            "List processes with ps aux, then read the two planted /decoys files.",
            "Review the returned values in Discovered inside the VM; inspect Argus activity separately.",
        ],
        "activity_cues": [
            "Process activity from uname, id, ps, or ls",
            "File access under /decoys when reported; no native detection is required",
        ],
        "duration": "Short action; process and file records may arrive later.",
    },
    "exec-memory": {
        "label": "Executable memory",
        "what": f"A Python process creates executable memory, writes inert bytes into it, and holds it for {EXEC_MEMORY_HOLD_SECONDS} seconds. It never executes those bytes.",
        "why": "Shows visibility into a memory condition associated with suspicious code loading.",
        "watch": "Native ‘New Executable Anonymous Memory Mapped’ record (EVENT/WARNING or ALERT/WARNING) for this workload and run, with writable and executable anonymous memory. A process-start record alone is insufficient.",
        "steps": [
            "Map an anonymous memory page with write and execute permissions.",
            f"Write inert bytes and keep the page mapped for {EXEC_MEMORY_HOLD_SECONDS} seconds; do not execute them.",
            "Compare the run with the exact native Argus memory record in Expected / Observed.",
        ],
        "activity_cues": [
            "The marked python3 /scripts/exec-memory.py process",
            "New Executable Anonymous Memory Mapped with writable and executable memory",
        ],
        "duration": f"About {EXEC_MEMORY_HOLD_SECONDS} seconds; Argus verification ends on a match or after 45 more seconds.",
    },
    "reverse-shell": {
        "label": "Reverse shell",
        "what": "Opens a command shell inside the VM and connects its input and output to the controlled demo server for up to 20 seconds.",
        "why": "Shows the remote-command channel pattern associated with control of a compromised workload.",
        "watch": "Related process and network events. Native detection requires a matching ‘Reverse Shell Detected’ ALERT/HIGH; running the action does not guarantee it.",
        "steps": [
            "Start an interactive Bash shell inside invisible-vm.",
            "Redirect its input and output to the in-namespace scenario-sink for up to 20 seconds.",
            "Inspect process and connection activity, then check the verified native alert result.",
        ],
        "activity_cues": [
            "The marked bash -i process and TCP connection to scenario-sink:4444",
            "Reverse Shell Detected ALERT/HIGH, if Argus emits it; the sink does not capture commands or live-session status",
        ],
        "duration": "Up to 20 seconds, plus up to 45 seconds for a native alert.",
    },
    "audit-evasion": {
        "label": "Audit evasion",
        "what": "Starts a temporary interactive shell, clears its disposable history, disables recording while running id, then restores history before exit.",
        "why": "Models an attempt to hide commands from shell history while the external observer keeps monitoring.",
        "watch": "Native ALERT/HIGH ‘Shell History Cleared’ or ‘Shell History Disabled’. Ordinary process events do not prove evasion detection.",
        "steps": [
            "Create a disposable history file and clear its harmless baseline.",
            "Disable shell history and run id while recording is off.",
            "Restore history recording, exit the shell, and remove the disposable file.",
        ],
        "activity_cues": [
            "The temporary Bash session and id process activity",
            "Shell History Cleared or Shell History Disabled ALERT/HIGH, if Argus emits it",
        ],
        "duration": "About 38 seconds, plus up to 45 seconds for a native alert.",
    },
}
