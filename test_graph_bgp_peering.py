from api.digital_twin import DigitalTwin


dt = DigitalTwin()

print()
print("BGP Peering")
print("=" * 60)

count = 0

for rel in dt.graph.relationships:

    if rel.type != "PEERS_WITH":
        continue

    bgp = dt.graph.nodes[rel.source]
    rif = dt.graph.nodes[rel.target]

    count += 1

    print()
    print(bgp.name)
    print("   -->", rif.name)
    print("   match:", rel.properties.get("match_type"))

print()
print("Peerings:", count)