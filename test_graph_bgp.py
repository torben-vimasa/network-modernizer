from api.digital_twin import DigitalTwin

dt = DigitalTwin()

print()
print("Firewall BGP")
print("=" * 60)

count = 0

for node in dt.graph.nodes.values():

    if node.type != "BGPNeighbor":
        continue

    count += 1

    print(
        node.name,
        "AS",
        node.properties["remote_as"],
        "-",
        node.properties["description"]
    )

print()
print("Neighbors:", count)