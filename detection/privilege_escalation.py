def detect_privilege_escalation(event):
    """
    Detects a successful change from a lower-privilege
    role to an administrative role.
    """

    if (
        event.get("event_type") == "PRIVILEGE_CHANGE"
        and event.get("action") == "role_changed"
        and event.get("status") == "success"
        and event.get("old_role") != "admin"
        and event.get("new_role") == "admin"
    ):
        return {
            "rule_id": "RULE-002",
            "event_id": event["event_id"],
            "user_id": event["user_id"],
            "stage": "Privilege Escalation",
            "risk_points": 20,
            "reason": (
                f"User {event['user_id']} changed privileges "
                f"from {event['old_role']} to {event['new_role']}."
            )
        }

    return None