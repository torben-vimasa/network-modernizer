from models.firewall_hop import FirewallHop
from models.trace_result import TraceResult


fw_hop = FirewallHop(
    firewall="UnknownFirewall",
    context="BDK-Mgmt",
    ingress_interface="CS",
    ip="10.255.255.17",
    subnet="10.255.255.16/29",
    reason="Next-hop resolved to ASA interface"
)

result = TraceResult(
    firewall_hops=[
        fw_hop
    ]
)

print()
print("TraceResult Firewall Hops")
print("=" * 50)

for hop in result.firewall_hops:
    print(hop)