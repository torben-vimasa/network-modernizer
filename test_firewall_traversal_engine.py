from api.digital_twin import DigitalTwin

from engines.firewall_traversal_engine import FirewallTraversalEngine

from models.firewall_hop import FirewallHop
from models.packet import Packet
from models.route_entry import RouteEntry


dt = DigitalTwin()

routes = [
    RouteEntry(
        router="BHASA1",
        vrf="BDK-Mgmt",
        prefix="100.72.36.64/27",
        next_hop="172.21.2.26",
        protocol="static"
    )
]

engine = FirewallTraversalEngine(
    twin=dt,
    routes=routes
)

packet = Packet(
    source="172.27.210.20",
    destination="100.72.36.70",
    protocol="object-group",
    service="Windows_Logging"
)

hop = FirewallHop(
    firewall="BHASA1",
    context="BDK-Mgmt",
    ingress_interface="CS",
    ip="10.255.255.17"
)

result = engine.traverse(
    hop,
    packet
)

print()
print("Firewall Traversal Engine")
print("=" * 60)

print("Permitted:", result.permitted)
print("Reason   :", result.reason)
print("Route    :", result.route)
print("NextHop  :", result.next_hop)
print("Egress   :", result.egress_interface)