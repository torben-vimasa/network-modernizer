from api.digital_twin import DigitalTwin
from engines.router_traversal_engine import RouterTraversalEngine


dt = DigitalTwin()

target = RouterTraversalEngine(dt).traverse(
    router="RGDCPe1",
    vrf="CS",
    destination="100.72.36.70"
)

print()
print("Router Traversal Engine")
print("=" * 60)
print(target)