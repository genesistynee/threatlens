import json
from pathlib import Path

from detection.unusual_login import detect_unusual_login
from detection.privilege_escalation import detect_privilege_escalation
from detection.sensitive_access import detect_sensitive_access
from detection.usb_activity import detect_usb_activity

from services.correlation import (
    correlate_sensitive_usb_activity,
    correlate_potential_exfiltration
)


def load_events(scenario="obvious_attack"):
    """Load security events from a selected scenario."""

    filenames = {
    "obvious_attack": "attack.json",
    "clean": "clean.json",
    "noisy_attack": "attack.json"
    }

    if scenario not in filenames:
        raise ValueError(f"Unknown scenario: {scenario}")

    data_file = (
        Path(__file__).parent.parent
        / "data"
        / "scenarios"
        / scenario
        / filenames[scenario]
    )

    with open(data_file, "r") as file:
        return json.load(file)  


def run_investigation(events):
    """
    Run all individual detection rules and correlation rules.
    """

    findings = []

    # --------------------------------
    # Individual event detections
    # --------------------------------

    for event in events:

        result = detect_unusual_login(event)
        if result:
            findings.append(result)

        result = detect_privilege_escalation(event)
        if result:
            findings.append(result)

        result = detect_sensitive_access(event)
        if result:
            findings.append(result)

        result = detect_usb_activity(event)
        if result:
            findings.append(result)

    # --------------------------------
    # Correlation detections
    # --------------------------------

    correlation_results = correlate_sensitive_usb_activity(events)
    findings.extend(correlation_results)

    correlation_results = correlate_potential_exfiltration(events)
    findings.extend(correlation_results)

    return findings