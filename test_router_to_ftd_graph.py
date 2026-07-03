from api.digital_twin import DigitalTwin


dt = DigitalTwin()

print()
print("Router to FTD Graph")
print("=" * 60)

for rel in dt.graph.relationships:

    if rel.type != "CONNECTED_TO":
        continue

    source = dt.graph.nodes.get(rel.source)
    target = dt.graph.nodes.get(rel.target)

    if not source or not target:
        continue

    pair = {source.type, target.type}

    if pair != {"RouterInterface", "ASAInterface"}:
        continue

    if "CAT3" not in source.name and "CAT3" not in target.name:
        continue

    print()
    print(source.name)
    print("  -->", target.name)