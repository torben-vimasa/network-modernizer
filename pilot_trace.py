import json
from pathlib import Path

from api.digital_twin import DigitalTwin
from reporters.trace_reporter import TraceReporter


flows_file = Path("pilots/pilot_flows.json")

with open(flows_file, encoding="utf-8") as f:
    flows = json.load(f)

dt = DigitalTwin()

print()
print("DIGITAL TWIN PILOT TRACE")
print("=" * 80)
print("Flows file :", flows_file)

for index, flow in enumerate(flows, start=1):

    print()
    print("=" * 80)
    print(f"FLOW {index}: {flow['name']}")
    print("=" * 80)
    print("Source     :", flow["source"])
    print("Destination:", flow["destination"])
    print("Service    :", flow["service"])

    result = dt.trace.trace(
        source=flow["source"],
        destination=flow["destination"],
        protocol=flow.get("protocol", "tcp"),
        service=flow.get("service", "Any"),
        router=flow.get("router", "RGDCPe1"),
        vrf=flow.get("vrf", "CS"),
        route_destination=flow.get(
            "route_destination",
            flow["destination"]
        ),
        max_hops=flow.get("max_hops", 8)
    )

    TraceReporter(result).print_console()