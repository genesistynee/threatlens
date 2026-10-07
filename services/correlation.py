from datetime import datetime


def parse_timestamp(timestamp):
    """Convert an ISO timestamp into a datetime object."""
    return datetime.fromisoformat(timestamp.replace("Z", "+00:00"))


def correlate_sensitive_usb_activity(events):
    """
    Finds a sequence where:

    1. A user accesses a highly sensitive file.
    2. A USB device is connected shortly afterward.
    3. The USB is connected to the same device.
    4. Both events belong to the same user.
    5. The events occur within 5 minutes.
    """

    suspicious_sequences = []

    for file_event in events:

        if not (
            file_event.get("event_type") == "FILE_ACCESS"
            and file_event.get("action") == "read"
            and file_event.get("status") == "success"
            and file_event.get("resource_sensitivity") == "high"
        ):
            continue

        file_time = parse_timestamp(file_event["timestamp"])

        for usb_event in events:

            if not (
                usb_event.get("event_type") == "USB"
                and usb_event.get("action") == "device_connected"
                and usb_event.get("status") == "success"
            ):
                continue

            if usb_event.get("user_id") != file_event.get("user_id"):
                continue

            if usb_event.get("device_id") != file_event.get("device_id"):
                continue

            usb_time = parse_timestamp(usb_event["timestamp"])

            time_difference = (
                usb_time - file_time
            ).total_seconds()

            if 0 <= time_difference <= 300:

                suspicious_sequences.append({
                    "correlation_rule": "CORR-001",
                    "stage": "Suspicious Removable Media Activity",
                    "user_id": file_event["user_id"],
                    "device_id": file_event["device_id"],
                    "file_event_id": file_event["event_id"],
                    "usb_event_id": usb_event["event_id"],
                    "time_difference_seconds": time_difference,
                    "risk_points": 20,
                    "reason": (
                        f"User accessed highly sensitive file "
                        f"'{file_event['resource']}' and connected a USB "
                        f"device {int(time_difference)} seconds later."
                    )
                })

    return suspicious_sequences


def correlate_potential_exfiltration(events):
    """
    Detects potential data exfiltration when:

    1. A highly sensitive file is accessed.
    2. A USB device is connected afterward.
    3. The same file is copied to that USB device.
    4. All events involve the same user and device.
    5. The sequence occurs within 5 minutes.
    """

    suspicious_sequences = []

    for file_event in events:

        if not (
            file_event.get("event_type") == "FILE_ACCESS"
            and file_event.get("action") == "read"
            and file_event.get("status") == "success"
            and file_event.get("resource_sensitivity") == "high"
        ):
            continue

        file_time = parse_timestamp(file_event["timestamp"])

        for usb_event in events:

            if not (
                usb_event.get("event_type") == "USB"
                and usb_event.get("action") == "device_connected"
                and usb_event.get("status") == "success"
            ):
                continue

            if usb_event.get("user_id") != file_event.get("user_id"):
                continue

            if usb_event.get("device_id") != file_event.get("device_id"):
                continue

            usb_time = parse_timestamp(usb_event["timestamp"])

            if usb_time <= file_time:
                continue

            for transfer_event in events:

                if not (
                    transfer_event.get("event_type") == "FILE_TRANSFER"
                    and transfer_event.get("action") == "copy"
                    and transfer_event.get("status") == "success"
                ):
                    continue

                if transfer_event.get("user_id") != file_event.get("user_id"):
                    continue

                if transfer_event.get("device_id") != file_event.get("device_id"):
                    continue

                if transfer_event.get("resource") != file_event.get("resource"):
                    continue

                if transfer_event.get("destination") != usb_event.get("resource"):
                    continue

                transfer_time = parse_timestamp(
                    transfer_event["timestamp"]
                )

                if transfer_time <= usb_time:
                    continue

                total_time = (
                    transfer_time - file_time
                ).total_seconds()

                if total_time > 300:
                    continue

                suspicious_sequences.append({
                    "correlation_rule": "CORR-002",
                    "user_id": file_event["user_id"],
                    "device_id": file_event["device_id"],
                    "file_event_id": file_event["event_id"],
                    "usb_event_id": usb_event["event_id"],
                    "transfer_event_id": transfer_event["event_id"],
                    "stage": "Potential Data Exfiltration",
                    "risk_points": 30,
                    "sequence_duration_seconds": total_time,
                    "reason": (
                        f"Highly sensitive file "
                        f"'{file_event['resource']}' was accessed, "
                        f"USB device '{usb_event['resource']}' was "
                        f"connected afterward, and the same file was "
                        f"copied to that USB device."
                    )
                })

    return suspicious_sequences