from services.investigation import load_events, run_investigation
from services.incident import build_incident


events = load_events()

findings = run_investigation(events)

incident = build_incident(events, findings)


print("=== THREATLENS INCIDENT ===")

print("Incident ID:", incident["incident_id"])
print("Severity:", incident["severity"])
print("Risk Score:", incident["risk_score"])
print("Users:", incident["users"])
print("Devices:", incident["devices"])
print("Start:", incident["start_time"])
print("End:", incident["end_time"])

print("\nAttack Stages:")

for number, stage in enumerate(
    incident["attack_stages"],
    start=1
):
    print(f"{number}. {stage}")


print("\nSupporting Evidence:")

for finding in incident["supporting_evidence"]:
    print(
        "-",
        finding.get("stage"),
        "|",
        finding.get("reason")
    )