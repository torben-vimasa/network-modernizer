from api.digital_twin import DigitalTwin


dt = DigitalTwin()

dt.load_directory("data/router_raw")

print()
print("=" * 60)

print("Graph Nodes         :", len(dt.graph.nodes))
print("Graph Relationships :", len(dt.graph.relationships))