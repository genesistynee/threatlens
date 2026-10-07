PRIMARY_STAGES = {
    "Suspicious Authentication",
    "Privilege Escalation",
    "Sensitive Resource Access",
    "Potential Data Exfiltration",
}


def build_critical_alert(findings):
    """
    Decide whether the verified findings form a high-confidence
    multi-stage attack.

    Individual events are not automatically treated as incidents.
    The alert is triggered by correlated evidence.
    """

    stages = {
        finding.get("stage")
        for finding in findings
    }

    evidence_ids = []

    for finding in findings:
        stage = finding.get("stage")

        if stage not in PRIMARY_STAGES:
            continue

        for key in [
            "event_id",
            "file_event_id",
            "usb_event_id",
            "transfer_event_id",
        ]:
            event_id = finding.get(key)

            if event_id and event_id not in evidence_ids:
                evidence_ids.append(event_id)

    has_authentication = "Suspicious Authentication" in stages
    has_privilege_escalation = "Privilege Escalation" in stages
    has_sensitive_access = "Sensitive Resource Access" in stages
    has_exfiltration = "Potential Data Exfiltration" in stages

    # Highest-confidence condition:
    # sensitive resource + USB-related exfiltration evidence
    if has_sensitive_access and has_exfiltration:

        if has_authentication and has_privilege_escalation:

            return {
                "alert": True,
                "level": "CRITICAL",
                "title": "High-Confidence Multi-Stage Attack Detected",
                "reason": (
                    "A suspicious authentication event and privilege "
                    "escalation were followed by sensitive resource access "
                    "and evidence of potential data exfiltration."
                ),
                "stages": [
                    "Suspicious Authentication",
                    "Privilege Escalation",
                    "Sensitive Resource Access",
                    "Potential Data Exfiltration",
                ],
                "evidence_event_ids": evidence_ids,
            }

        return {
            "alert": True,
            "level": "CRITICAL",
            "title": "Potential Data Exfiltration Detected",
            "reason": (
                "A sensitive resource was accessed and correlated "
                "removable-media activity indicates potential data "
                "exfiltration."
            ),
            "stages": [
                "Sensitive Resource Access",
                "Potential Data Exfiltration",
            ],
            "evidence_event_ids": evidence_ids,
        }

    # Not enough correlated evidence for a critical alert.
    return {
        "alert": False,
        "level": "NORMAL",
        "title": "No Critical Alert",
        "reason": (
            "No sufficiently strong multi-stage attack chain "
            "was established."
        ),
        "stages": [],
        "evidence_event_ids": evidence_ids,
    }