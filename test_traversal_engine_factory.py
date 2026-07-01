from api.digital_twin import DigitalTwin
from engines.traversal_engine_factory import TraversalEngineFactory


dt = DigitalTwin()

factory = TraversalEngineFactory(dt)

print()
print("Traversal Engine Factory")
print("=" * 60)

for device_type in [
    "Router",
    "Firewall",
    "Switch",
    None
]:
    print()
    print("Device type:", device_type)
    print("Engine     :", factory.get_engine(device_type))