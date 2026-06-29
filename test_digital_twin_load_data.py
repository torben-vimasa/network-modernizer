from api.digital_twin import DigitalTwin


dt = DigitalTwin()

dt.load_directory("data")

print()
print("DigitalTwin load data")
print("=" * 60)

print("Graph nodes :", len(dt.graph.nodes))
print("Graph rels  :", len(dt.graph.relationships))