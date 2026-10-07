import json
from pathlib import Path

from services.investigation import run_investigation
from services.timeline import build_attack_timeline


data_file = (
    Path(__file__).parent
    / "data"
    / "scenarios"
    / "obvious_attack"
    / "attack.json"
)

with open(data_file, "r") as file:
    events = json.load(file)


findings = run_investigation(events)

timeline = build_attack_timeline(events, findings)


print("=== THREATLENS ATTACK TIMELINE ===")

for number, step in enumerate(timeline, start=1):

    print(f"\nStep {number}")
    print("Time:", step["timestamp"])
    print("Stage:", step["stage"])
    print("Evidence:", step["evidence_event_ids"])
    print("Reason:", step["reason"])