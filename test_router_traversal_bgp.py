from api.digital_twin import DigitalTwin
from engines.router_traversal_engine import RouterTraversalEngine


dt = DigitalTwin()

target = RouterTraversalEngine(dt).traverse(
    router="RGDCPe1",
    vrf="SPNS2-TRANSIT-JTTN",
    destination="100.73.32.10"
)

print()
print("Router BGP Traversal")
print("=" * 60)
print(target)