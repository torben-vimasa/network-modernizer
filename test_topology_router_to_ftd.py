from api.digital_twin import DigitalTwin
from engines.topology_traversal_engine import TopologyTraversalEngine


dt = DigitalTwin()
topology = TopologyTraversalEngine(dt.graph)

for context, interface in [
    ("RGDCPe1", "Vlan3100"),
    ("RGDCPe1", "Vlan3101"),
    ("RGDCPe1", "Vlan3102"),
    ("OBvDCPe1", "Vlan3100"),
]:
    print()
    print("Router interface:", context, interface)
    print(topology.find_connected_device(context, interface))