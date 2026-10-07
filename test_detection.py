from detection.usb_activity import detect_usb_activity
from detection.sensitive_access import detect_sensitive_access
from detection.privilege_escalation import detect_privilege_escalation
import json
from pathlib import Path

from detection.unusual_login import detect_unusual_login


data_file = (
    Path(__file__).parent
    / "data"
    / "scenarios"
    / "obvious_attack"
    / "attack.json"
)

with open(data_file, "r") as file:
    events = json.load(file)


for event in events:
    result = detect_unusual_login(event)

    if result:
        print("🚨 SUSPICIOUS EVENT DETECTED")
        print(result)




   
print("\n--- Testing a normal login ---")

normal_login = {
    "event_id": "TEST-001",
    "user_id": "alice",
    "event_type": "LOGIN",
    "action": "successful_login",
    "country": "India",
    "usual_country": "India"
}

result = detect_unusual_login(normal_login)

if result:
    print("🚨 FALSE POSITIVE")
    print(result)
else:
    print("✅ Normal login correctly ignored")



print("\n--- Testing privilege escalation ---")

privilege_event = {
    "event_id": "TEST-002",
    "user_id": "alice",
    "event_type": "PRIVILEGE_CHANGE",
    "action": "role_changed",
    "status": "success",
    "old_role": "employee",
    "new_role": "admin"
}

result = detect_privilege_escalation(privilege_event)

if result:
    print("🚨 PRIVILEGE ESCALATION DETECTED")
    print(result)
else:
    print("❌ Privilege escalation was not detected")



print("\n--- Testing normal role change ---")

normal_role_change = {
    "event_id": "TEST-003",
    "user_id": "bob",
    "event_type": "PRIVILEGE_CHANGE",
    "action": "role_changed",
    "status": "success",
    "old_role": "employee",
    "new_role": "employee"
}

result = detect_privilege_escalation(normal_role_change)

if result:
    print("🚨 FALSE POSITIVE")
    print(result)
else:
    print("✅ Normal role change correctly ignored")



print("\n--- Testing sensitive file access ---")

sensitive_event = {
    "event_id": "TEST-004",
    "user_id": "alice",
    "event_type": "FILE_ACCESS",
    "action": "read",
    "status": "success",
    "resource": "payroll_2026.xlsx",
    "resource_sensitivity": "high"
}

result = detect_sensitive_access(sensitive_event)

if result:
    print("🚨 SENSITIVE RESOURCE ACCESS DETECTED")
    print(result)
else:
    print("❌ Sensitive access was not detected")




print("\n--- Testing normal file access ---")

normal_file_access = {
    "event_id": "TEST-005",
    "user_id": "alice",
    "event_type": "FILE_ACCESS",
    "action": "read",
    "status": "success",
    "resource": "team_schedule.txt",
    "resource_sensitivity": "normal"
}

result = detect_sensitive_access(normal_file_access)

if result:
    print("🚨 FALSE POSITIVE")
    print(result)
else:
    print("✅ Normal file access correctly ignored")



print("\n--- Testing USB activity ---")

usb_event = {
    "event_id": "TEST-006",
    "user_id": "alice",
    "device_id": "LAPTOP-07",
    "event_type": "USB",
    "action": "device_connected",
    "status": "success",
    "resource": "USB-8821"
}

result = detect_usb_activity(usb_event)

if result:
    print("⚠️ USB ACTIVITY DETECTED")
    print(result)
else:
    print("❌ USB activity was not detected")


print("\n--- Testing unrelated event ---")

unrelated_event = {
    "event_id": "TEST-007",
    "user_id": "alice",
    "event_type": "LOGIN",
    "action": "successful_login",
    "status": "success",
    "country": "India",
    "usual_country": "India"
}

result = detect_usb_activity(unrelated_event)

if result:
    print("🚨 FALSE POSITIVE")
    print(result)
else:
    print("✅ Non-USB event correctly ignored")