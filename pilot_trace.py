import json
from pathlib import Path

from api.digital_twin import DigitalTwin
from reporters.trace_reporter import TraceReporter


flows_file = Path("pilot_flows.json")

with open(flows_file, encoding="utf-8") as f:
    flows = json.load(f)

dt = DigitalTwin()

print()
print("DIGITAL TWIN PILOT TRACE")
print("=" * 80)

for index, flow in enumerate(flows, start=1):

    print()
    print("=" * 80)
    print(f"FLOW {index}: {flow['name']}")
    print("=" * 80)
    print("Source     :", flow["src"])
    print("Destination:", flow["dst"])
    print("Service    :", flow["service"])

    result = dt.trace.trace(
        source=flow["src"],
        destination=flow["dst"],
        protocol=flow["protocol"],
        service=flow["service"],
        router=flow["router"],
        vrf=flow["vrf"],
        route_destination=flow["route_destination"],
        max_hops=8
    )

    TraceReporter(result).print_console()