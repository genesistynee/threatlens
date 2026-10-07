from datetime import datetime


def parse_timestamp(timestamp):
    """Convert an ISO timestamp into a datetime object."""
    return datetime.fromisoformat(timestamp.replace("Z", "+00:00"))


def build_attack_timeline(events, findings):
    """
    Build an ordered attack timeline from detection
    and correlation findings.

    Each timeline entry contains:
    - timestamp
    - stage
    - evidence event IDs
    - explanation
    """

    timeline = []

    event_lookup = {
        event["event_id"]: event
        for event in events
        if event.get("event_id")
    }

    for finding in findings:

        if finding.get("stage")in[
            "Removable Media Activity",
            "Suspicious Removable Media Activity"
        ]:
            continue

        evidence_event_ids = []

        if finding.get("event_id"):
            evidence_event_ids.append(
                finding["event_id"]
            )

        if finding.get("file_event_id"):
            evidence_event_ids.append(
                finding["file_event_id"]
            )

        if finding.get("usb_event_id"):
            evidence_event_ids.append(
                finding["usb_event_id"]
            )

        if finding.get("transfer_event_id"):
            evidence_event_ids.append(
                finding["transfer_event_id"]
            )

        evidence_events = [
            event_lookup[event_id]
            for event_id in evidence_event_ids
            if event_id in event_lookup
        ]

        if not evidence_events:
            continue

        timeline_event = max(
            evidence_events,
            key=lambda event: parse_timestamp(event["timestamp"])
)

        timeline.append({
            "timestamp": timeline_event["timestamp"],
            "stage": finding.get("stage"),
            "evidence_event_ids": evidence_event_ids,
            "reason": finding.get("reason")
        })

    timeline.sort(
        key=lambda item: parse_timestamp(item["timestamp"])
    )

    return timeline