from api.digital_twin import DigitalTwin
from engines.router_traversal_engine import RouterTraversalEngine


dt = DigitalTwin()
engine = RouterTraversalEngine(dt)

for next_hop in [
    "100.73.0.2",
    "100.73.0.10",
    "100.73.0.18",
    "100.73.32.2",
]:
    target = engine._resolve_next_hop(next_hop)

    print()
    print("Next-hop:", next_hop)
    print(target)