from services.investigation import load_events, run_investigation
from services.risk import calculate_risk


events = load_events()

findings = run_investigation(events)

risk = calculate_risk(findings)


print("=== THREATLENS RISK ASSESSMENT ===")

print("Risk Score:", risk["risk_score"])
print("Severity:", risk["severity"])

print("\nRisk Factors:")

for factor in risk["factors"]:
    print("-", factor)