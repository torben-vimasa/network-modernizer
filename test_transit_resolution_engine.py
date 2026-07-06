from api.digital_twin import DigitalTwin
from engines.transit_resolution_engine import TransitResolutionEngine


dt = DigitalTwin()
engine = TransitResolutionEngine(dt.graph)

for next_hop in [
    "10.255.255.163",
    "10.255.255.161",
    "100.73.0.2",
    "100.73.0.18"
]:
    print()
    print("Next-hop:", next_hop)
    print("=" * 60)

    result = engine.candidates_for_next_hop(
        next_hop,
        exclude_device="BHASA1"
    )

    print(result)