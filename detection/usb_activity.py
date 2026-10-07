def detect_usb_activity(event):
    """
    Detects a USB device connection.

    A USB connection alone is not proof of an attack.
    This rule produces a low-confidence security signal
    that can be correlated with other events later.
    """

    if (
        event.get("event_type") == "USB"
        and event.get("action") == "device_connected"
        and event.get("status") == "success"
    ):
        return {
            "rule_id": "RULE-004",
            "event_id": event["event_id"],
            "user_id": event["user_id"],
            "stage": "Removable Media Activity",
            "risk_points": 5,
            "reason": (
                f"USB device '{event['resource']}' was connected "
                f"by user {event['user_id']}."
            )
        }

    return None