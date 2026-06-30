from api.digital_twin import DigitalTwin
from engines.source_locator_engine import SourceLocatorEngine


dt = DigitalTwin()

dt.load_directory("data/router_raw")

locator = SourceLocatorEngine(dt.graph)

for source in [
    "172.27.210.20",
    "172.21.2.26",
    "10.255.255.17",
]:
    result = locator.locate(source)

    print()
    print("Source:", source)
    print("=" * 60)
    print(result)