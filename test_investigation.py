from services.investigation import load_events, run_investigation


events = load_events()

findings = run_investigation(events)


print("=== THREATLENS INVESTIGATION ===")
print(f"Events analyzed: {len(events)}")
print(f"Findings generated: {len(findings)}")
print()

for finding in findings:
    print(
        finding.get("rule_id")
        or finding.get("correlation_rule"),
        "|",
        finding.get("stage"),
        "|",
        finding.get("event_id")
        or finding.get("file_event_id")
    )