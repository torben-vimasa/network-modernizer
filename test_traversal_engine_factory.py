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
    engine = factory.get_engine(device_type)

    print()
    print("Device type:", device_type)
    print("Engine     :", type(engine).__name__ if engine else None)