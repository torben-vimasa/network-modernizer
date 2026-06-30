from models.firewall_traversal_result import FirewallTraversalResult


result = FirewallTraversalResult(
    firewall="BHASA1",
    context="BDK-Mgmt",
    ingress_interface="CS",
    egress_interface="Transit",
    source_before="172.27.210.20",
    source_after="10.255.255.17",
    destination_before="100.72.36.70",
    destination_after="100.72.36.70",
    route="100.72.36.64/27",
    next_hop="172.21.2.62",
    permitted=True,
    reason="Firewall traversal completed"
)

print()
print("Firewall Traversal Result")
print("=" * 60)
print(result)