from api.digital_twin import DigitalTwin


dt = DigitalTwin()

print()
print("Connected Network Interfaces")
print("=" * 60)

count = 0

for rel in dt.graph.relationships:

    if rel.type != "CONNECTED_TO":
        continue

    source = dt.graph.nodes.get(rel.source)
    target = dt.graph.nodes.get(rel.target)

    if not source or not target:
        continue

    if source.type not in ["RouterInterface", "ASAInterface", "Interface"]:
        continue

    if target.type not in ["RouterInterface", "ASAInterface", "Interface"]:
        continue

    count += 1

    print()
    print(source.name)
    print("  -->", target.name)

print()
print("NETWORK CONNECTED_TO:", count)