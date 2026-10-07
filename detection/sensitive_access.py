def detect_sensitive_access(event):
    """
    Detects successful access to a highly sensitive resource.
    """

    if (
        event.get("event_type") == "FILE_ACCESS"
        and event.get("action") == "read"
        and event.get("status") == "success"
        and event.get("resource_sensitivity") == "high"
    ):
        return {
            "rule_id": "RULE-003",
            "event_id": event["event_id"],
            "user_id": event["user_id"],
            "stage": "Sensitive Resource Access",
            "risk_points": 15,
            "reason": (
                f"User {event['user_id']} accessed highly "
                f"sensitive resource '{event['resource']}'."
            )
        }

    return None