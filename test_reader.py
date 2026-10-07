import json
from pathlib import Path

data_file = Path(__file__).parent / "data" / "scenarios" / "obvious_attack" / "attack.json"

with open(data_file, "r") as file:
    events = json.load(file)

print(f"Loaded {len(events)} events.\n")

for event in events:
    print(
        event["timestamp"],
        "|",
        event["user_id"],
        "|",
        event["event_type"],
        "|",
        event["action"]
    )