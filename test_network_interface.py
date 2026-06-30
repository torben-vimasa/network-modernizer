from models.network_interface import NetworkInterface


interface = NetworkInterface(
    device="OBvDCPe1",
    name="TenGigE0/0/0/10",
    ip="172.21.2.26",
    subnet="172.21.2.16/28",
    vrf="CS",
    interface_type="router",
    raw="interface TenGigE0/0/0/10"
)

print()
print("Network Interface")
print("=" * 60)
print(interface)