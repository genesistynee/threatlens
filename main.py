
import json
import sys
from pathlib import Path

from services.investigation import load_events, run_investigation
from services.incident import build_incident
from services.timeline import build_attack_timeline
from services.evidence import build_evidence_map
from graph.builder import build_attack_graph
from ai.explainer import explain_findings
from services.alert import build_critical_alert


def main():

    print("\n" + "=" * 60)
    print("                 THREATLENS")
    print("        Evidence-Based Cyber Threat Intelligence")
    print("=" * 60)

    # --------------------------------------------------
    # 1. LOAD SECURITY EVENTS
    # --------------------------------------------------

    scenario = sys.argv[1] if len(sys.argv) > 1 else "obvious_attack"

    events = load_events(scenario)

    print(f"\n📥 Loaded {len(events)} security events.")

    # --------------------------------------------------
    # 2. RUN DETECTION + CORRELATION
    # --------------------------------------------------

    findings = run_investigation(events)

    print(f"🔎 Generated {len(findings)} security findings.")

    # --------------------------------------------------
    # 3. BUILD INCIDENT
    # --------------------------------------------------

    incident = build_incident(events, findings)
    alert = build_critical_alert(findings)

    if not incident:
        print("\n✅ No incident detected.")

        if alert["alert"]:
            print("\n🚨 CRITICAL ALERT")
            print(f"Level  : {alert['level']}")
            print(f"Title  : {alert['title']}")
            print(f"Reason : {alert['reason']}")
            print(f"Evidence: {alert['evidence_event_ids']}")

        return

    if alert["alert"]:
        print("\n" + "=" * 60)
        print("🚨 SPECIAL SECURITY ALERT")
        print("=" * 60)

        print(f"Level    : {alert['level']}")
        print(f"Alert    : {alert['title']}")
        print(f"Reason   : {alert['reason']}")

        print("\nAttack stages:")
        for stage in alert["stages"]:
            print(f"  ✓ {stage}")

        print("\nEvidence:")
        for event_id in alert["evidence_event_ids"]:
            print(f"  ✓ {event_id}")

    print("\n" + "=" * 60)
    print("🚨 INCIDENT DETECTED")
    print("=" * 60)

    print(f"Incident ID : {incident['incident_id']}")
    print(f"Severity    : {incident['severity']}")
    print(f"Risk Score  : {incident['risk_score']}")

    print(f"Users       : {', '.join(incident['users'])}")
    print(f"Devices     : {', '.join(incident['devices'])}")

    # --------------------------------------------------
    # 4. ATTACK TIMELINE
    # --------------------------------------------------

    timeline = build_attack_timeline(events, findings)

    print("\n" + "=" * 60)
    print("📅 ATTACK TIMELINE")
    print("=" * 60)

    for index, step in enumerate(timeline, start=1):

        print(f"\nStep {index}")
        print(f"Time     : {step['timestamp']}")
        print(f"Stage    : {step['stage']}")
        print(f"Evidence : {step['evidence_event_ids']}")
        print(f"Reason   : {step['reason']}")

    # --------------------------------------------------
    # --------------------------------------------------
    # 5. EVIDENCE MAP
    # --------------------------------------------------

    evidence_map = build_evidence_map(events, findings)

    print("\n" + "=" * 60)
    print("🔬 EVIDENCE MAP")
    print("=" * 60)

    for evidence in evidence_map:

        print(f"\nStage    : {evidence['stage']}")
        print(f"Evidence : {evidence['evidence_event_ids']}")
        print(f"Reason   : {evidence['reason']}")

    # --------------------------------------------------
    # 6. ATTACK GRAPH
    # --------------------------------------------------

    graph = build_attack_graph(events)

    print("\n" + "=" * 60)
    print("🕸️ ATTACK GRAPH")
    print("=" * 60)

    print("\nNodes:")

    for node in graph["nodes"]:
        print(f"  {node['id']} [{node['type']}]")

    print("\nRelationships:")

    for edge in graph["edges"]:
        print(
            f"  {edge['source']} "
            f"-- {edge['relationship']} --> "
            f"{edge['target']}"
        )

    # --------------------------------------------------
    # 6B. AI-ASSISTED EXPLANATION
    # --------------------------------------------------

    explanations = explain_findings(findings)

    primary_stages = {
        "Suspicious Authentication",
        "Privilege Escalation",
        "Sensitive Resource Access",
        "Potential Data Exfiltration",
    }

    print("\n" + "=" * 60)
    print("🤖 AI-ASSISTED EXPLANATION")
    print("=" * 60)

    for explanation in explanations:

        if explanation["stage"] not in primary_stages:
            continue

        print(f"\nStage    : {explanation['stage']}")
        print(f"Evidence : {explanation['evidence_event_ids']}")
        print(f"Source   : {explanation['source']}")
        print(f"Explanation: {explanation['explanation']}")

    print("\n" + "=" * 60)
    print("🛡️ RECOMMENDED ACTION")
    print("=" * 60)

    if incident["severity"] == "Critical":

        print("""
1. Investigate and potentially disable the affected account.
2. Revoke unexpected administrative privileges.
3. Isolate or investigate the affected device.
4. Inspect the connected removable media.
5. Investigate the sensitive file transfer.
6. Review related authentication activity.
""")

    elif incident["severity"] == "High":

        print("""
1. Investigate the affected account.
2. Review privilege changes.
3. Inspect the affected device.
4. Review sensitive resource access.
""")

    else:

        print("""
1. Review the detected activity.
2. Validate whether the behavior is expected.
3. Continue monitoring related events.
""")

    print("=" * 60)
    print("              INVESTIGATION COMPLETE")
    print("=" * 60)


if __name__ == "__main__":
    main()