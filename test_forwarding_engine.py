from api.digital_twin import DigitalTwin
from engines.forwarding_engine import ForwardingEngine

dt = DigitalTwin()
engine = ForwardingEngine(dt.graph)

for ip in [
    "100.73.0.1",
    "100.73.0.2",
    "100.73.0.10",
    "100.73.0.17",
    "100.73.0.18",
]:
    print()
    print(ip)
    print(engine.resolve_next_hop(
        current_device="none",
        next_hop=ip
    ))