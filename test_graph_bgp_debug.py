from api.digital_twin import DigitalTwin

dt = DigitalTwin()

print()
print("BGP Peer Debug")
print("=" * 60)

peers = [
    n.name for n in dt.graph.nodes.values()
    if n.type == "BGPNeighbor"
]

print("BGP peers:", len(peers))
print(peers[:10])

print()
print("Router interface IPs containing 100.73.0")
print("-" * 60)

for node in dt.graph.nodes.values():
    if node.type not in ["RouterInterface", "Interface"]:
        continue

    ip = node.properties.get("ip")

    if ip and "100.73.0" in ip:
        print(node.name, ip)