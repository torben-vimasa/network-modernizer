from api.digital_twin import DigitalTwin


dt = DigitalTwin()

result = dt.load_router(
    "data/router_raw/OBvDCPe1-20260424.txt"
)

print()
print("Interface Import Debug")
print("=" * 60)

print("Imported interfaces:", len(result.interfaces))

print()
print("Interfaces containing 172.21.2")
print("-" * 60)

for interface in result.interfaces:
    text = f"{interface.name} {interface.ip} {interface.subnet}"
    if "172.21.2" in text:
        print(interface)

print()
print("Graph IP lookup")
print("-" * 60)

ip_node = dt.graph.find("IPAddress", "172.21.2.26")

print(ip_node)

if ip_node:
    for relation, neighbor in dt.graph.neighbors(ip_node.id):
        print(relation, neighbor)