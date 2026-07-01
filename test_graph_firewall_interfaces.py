from api.digital_twin import DigitalTwin


dt = DigitalTwin()

print()
print("Graph Firewall Interfaces")
print("=" * 60)

count = 0

for node in dt.graph.nodes.values():
    if node.type == "ASAInterface" and "CAT3" in node.name:
        count += 1

print("CAT3 firewall interfaces:", count)

for node in dt.graph.nodes.values():
    if node.type == "ASAInterface" and "TRANSIT" in node.name:
        print()
        print("Interface:", node.name)
        print("IP       :", node.properties.get("ip"))
        print("Mask     :", node.properties.get("mask"))
        print("VLAN     :", node.properties.get("vlan"))