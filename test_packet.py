from models.packet import Packet


packet = Packet(
    source="172.27.210.20",
    destination="100.72.36.70",
    protocol="tcp",
    service="ssh",
    current_router="RGDCPe1",
    current_vrf="CS"
)

packet.add_history("Packet created")
packet.add_history("Ready for trace")

print()
print("Packet Test")
print("=" * 40)
print("Source :", packet.source)
print("Dest   :", packet.destination)
print("Router :", packet.current_router)
print("VRF    :", packet.current_vrf)

print()
print("History")
print("-" * 40)

for item in packet.history:
    print(item)