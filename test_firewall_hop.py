from models.firewall_hop import FirewallHop


hop = FirewallHop(
    firewall="UnknownFirewall",
    context="BDK-Mgmt",
    ingress_interface="CS",
    ip="10.255.255.17",
    subnet="10.255.255.16/29",
    reason="Next-hop resolved to ASA interface"
)

print()
print("Firewall Hop")
print("=" * 50)
print(hop)