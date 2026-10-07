from pathlib import Path

import json

from graph.builder import build_attack_graph


data_file = (
    Path(__file__).parent
    / "data"
    / "scenarios"
    / "obvious_attack"
    / "attack.json"
)


with open(data_file, "r") as file:
    events = json.load(file)


graph = build_attack_graph(events)


print("=== THREATLENS ATTACK GRAPH ===")

print("\nNODES:")
for node in graph["nodes"]:
    print(node)

print("\nEDGES:")
for edge in graph["edges"]:
    print(edge)