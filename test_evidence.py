from services.investigation import load_events, run_investigation
from services.evidence import build_evidence_map


events = load_events()

findings = run_investigation(events)

evidence_map = build_evidence_map(events, findings)


print("=== THREATLENS EVIDENCE MAP ===")

for item in evidence_map:
    print("\nStage:", item["stage"])
    print("Evidence:", item["evidence_event_ids"])
    print("Reason:", item["reason"])