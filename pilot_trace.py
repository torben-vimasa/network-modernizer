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
print(f"Flows file : {flows_file}")

for index, flow in enumerate(flows, start=1):

    print()
    print("=" * 80)
    print(f"FLOW {index}: {flow['name']}")
    print("=" * 80)
    src = flow.get("src") or flow.get("source")
    dst = flow.get("dst") or flow.get("destination")

    print("Source     :", src)
    print("Destination:", dst)
    print("Service    :", flow.get("service", "Any"))

    kwargs = {
        "source": src,
        "destination": dst,
        "protocol": flow.get("protocol"),
        "service": flow.get("service"),
        "max_hops": flow.get("max_hops", 12)
    }

    #
    # Backwards compatibility
    #
    if "router" in flow:
        kwargs["router"] = flow["router"]

    if "vrf" in flow:
        kwargs["vrf"] = flow["vrf"]

    if "route_destination" in flow:
        kwargs["route_destination"] = flow["route_destination"]

    result = dt.trace.trace(**kwargs)

    TraceReporter(result).print_console()