def detect_unusual_login(event):
    """
    Detects a successful login from a country
    different from the user's usual country.
    """

    if (
        event.get("event_type") == "LOGIN"
        and event.get("action") == "successful_login"
        and event.get("country")
        and event.get("usual_country")
        and event.get("country") != event.get("usual_country")
    ):
        return {
            "rule_id": "RULE-001",
            "event_id": event["event_id"],
            "user_id": event["user_id"],
            "stage": "Suspicious Authentication",
            "risk_points": 25,
            "reason": (
                f"Successful login from {event['country']}; "
                f"user normally logs in from {event['usual_country']}."
            )
        }

    return None