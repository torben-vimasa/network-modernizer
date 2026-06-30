from api.digital_twin import DigitalTwin

from engines.firewall_traversal_engine import FirewallTraversalEngine

from models.firewall_hop import FirewallHop
from models.packet import Packet


dt = DigitalTwin()

engine = FirewallTraversalEngine(dt)

packet = Packet(
    source="172.27.210.20",
    destination="100.72.36.70"
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

print("Permitted :", result.permitted)
print("Reason    :", result.reason)
print()

print(result.security)
print()

print(result.nat)