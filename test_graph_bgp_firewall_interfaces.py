from api.digital_twin import DigitalTwin


dt = DigitalTwin()

print()
print("BGP Firewall Interfaces")
print("=" * 60)

count = 0

for rel in dt.graph.relationships:

    if rel.type != "BGP_ON_INTERFACE":
        continue

    bgp = dt.graph.nodes[rel.source]
    fw_if = dt.graph.nodes[rel.target]

    count += 1

    print()
    print(bgp.name)
    print("   -->", fw_if.name)

print()
print("BGP_ON_INTERFACE:", count)