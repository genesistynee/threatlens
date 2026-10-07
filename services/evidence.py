def build_evidence_map(events, findings):
    """
    Map each attack stage to the event evidence
    that supports it.
    """

    evidence_map = []

    for finding in findings:

        stage = finding.get("stage")

        if stage in [
            "Removable Media Activity",
            "Suspicious Removable Media Activity"
        ]:
            continue

        event_ids = []

        if finding.get("event_id"):
            event_ids.append(finding["event_id"])

        if finding.get("file_event_id"):
            event_ids.append(finding["file_event_id"])

        if finding.get("usb_event_id"):
            event_ids.append(finding["usb_event_id"])

        if finding.get("transfer_event_id"):
            event_ids.append(finding["transfer_event_id"])

        evidence_map.append({
            "stage": stage,
            "evidence_event_ids": event_ids,
            "reason": finding.get("reason")
        })

    return evidence_map