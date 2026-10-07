from services.risk import calculate_risk
from datetime import datetime


def parse_timestamp(timestamp):
    """Convert an ISO timestamp into a datetime object."""
    return datetime.fromisoformat(timestamp.replace("Z", "+00:00"))


def build_incident(events, findings):
    if not events:
        return None

    primary_stages = {
        "Suspicious Authentication",
        "Privilege Escalation",
        "Sensitive Resource Access",
        "Potential Data Exfiltration",
    }

    if not any(
        finding.get("stage") in primary_stages
        for finding in findings
    ):
        return None

    incident_id = "INC-000001"

    attack_event_ids = set()

    for finding in findings:
        if finding.get("stage") not in primary_stages:
            continue

        for key in [
            "event_id",
            "file_event_id",
            "usb_event_id",
            "transfer_event_id",
        ]:
            event_id = finding.get(key)

            if event_id:
                attack_event_ids.add(event_id)

    attack_events = [
        event
        for event in events
        if event.get("event_id") in attack_event_ids
    ]

    users = sorted({
        event.get("user_id")
        for event in attack_events
        if event.get("user_id")
    })

    devices = sorted({
        event.get("device_id")
        for event in attack_events
        if event.get("device_id")
    })

    timestamps = [
        parse_timestamp(event["timestamp"])
        for event in attack_events
        if event.get("timestamp")
    ]

    if not timestamps:
        start_time = None
        end_time = None
    else:
        start_time = min(timestamps).isoformat()
        end_time = max(timestamps).isoformat()

    attack_stages = []
    supporting_evidence = []

    for finding in findings:
        stage = finding.get("stage")

        if stage in primary_stages:
            if stage not in attack_stages:
                attack_stages.append(stage)

        elif stage in {
            "Removable Media Activity",
            "Suspicious Removable Media Activity",
        }:
            supporting_evidence.append(finding)

    evidence = sorted(attack_event_ids)

    risk = calculate_risk(findings)

    risk_score = risk["risk_score"]
    severity = risk["severity"]

    return {
        "incident_id": incident_id,
        "severity": severity,
        "risk_score": risk_score,
        "users": users,
        "devices": devices,
        "start_time": start_time,
        "end_time": end_time,
        "attack_stages": attack_stages,
        "supporting_evidence": supporting_evidence,
        "evidence": evidence,
        "findings": findings,
    }
