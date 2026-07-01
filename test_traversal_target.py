from models.traversal_target import TraversalTarget


target = TraversalTarget(
    device_name="RGDCPe1",
    device_type="Router",
    interface="Vlan859",
    vrf="SPNS2-TRANSIT-JTTN",
    method="topology_connected_to",
    confidence="high",
    reason="Firewall egress is connected to router interface"
)

print()
print("Traversal Target")
print("=" * 60)
print(target)