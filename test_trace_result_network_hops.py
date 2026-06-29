from models.network_hop import NetworkHop
from models.trace_result import TraceResult


result = TraceResult(
    network_hops=[
        NetworkHop(
            hop_number=1,
            hop_type="router",
            device="RGDCPe1",
            vrf="CS",
            route="100.72.36.64/27",
            next_hop="10.255.255.17",
            reason="Matched route"
        ),
        NetworkHop(
            hop_number=2,
            hop_type="firewall",
            device="UnknownFirewall",
            context="BDK-Mgmt",
            ingress_interface="CS",
            ip="10.255.255.17",
            subnet="10.255.255.16/28",
            reason="Next-hop resolved to ASA interface"
        )
    ]
)

print()
print("TraceResult Network Hops")
print("=" * 50)

for hop in result.network_hops:
    print(hop)