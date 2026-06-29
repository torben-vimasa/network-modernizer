from api.digital_twin import DigitalTwin


dt = DigitalTwin()
dt.load_directory("data")

types = {}

for node in dt.graph.nodes.values():
    types[node.type] = types.get(node.type, 0) + 1

print()
print("Inventory Report")
print("=" * 60)

print("Total nodes        :", len(dt.graph.nodes))
print("Total relationships:", len(dt.graph.relationships))

print()
print("Node types")
print("-" * 60)

for node_type, count in sorted(types.items()):
    print(f"{node_type:20} {count}")