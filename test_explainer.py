from services.investigation import load_events, run_investigation
from ai.explainer import explain_findings


events = load_events("noisy_attack")
findings = run_investigation(events)

explanations = explain_findings(findings)

for item in explanations:
    print("\n" + "=" * 60)
    print(f"Stage    : {item['stage']}")
    print(f"Evidence : {item['evidence_event_ids']}")
    print(f"Explanation: {item['explanation']}")