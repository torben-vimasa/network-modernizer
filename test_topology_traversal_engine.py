from api.digital_twin import DigitalTwin
from engines.topology_traversal_engine import TopologyTraversalEngine


dt = DigitalTwin()

engine = TopologyTraversalEngine(dt.graph)

for context, interface in [
    ("BDK-Mgmt", "CS"),
    ("BDK-Mgmt", "SPNS2-TRANSIT-JTTN"),
    ("BDK-Mgmt", "spns2-transit-jttn"),
]:
    result = engine.find_connected_device(
        context=context,
        interface_name=interface
    )

    print()
    print("Topology Traversal")
    print("=" * 60)
    print("Context  :", context)
    print("Interface:", interface)
    print(result)