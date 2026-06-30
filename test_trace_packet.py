from api.digital_twin import DigitalTwin
from models.route_entry import RouteEntry


dt = DigitalTwin()

dt.firewall_routes = [
    RouteEntry(
        router="BHASA1",
        vrf="BDK-Mgmt",
        prefix="100.72.36.64/27",
        next_hop="10.255.255.163",
        protocol="static"
    )
]

dt.firewall_interfaces = [
    {
        "name": "CS",
        "subnet": "10.255.255.16/28"
    },
    {
        "name": "spns2-transit-jttn",
        "subnet": "10.255.255.160/28"
    }
]

result = dt.trace_packet(
    source="172.27.210.20",
    destination="SPNS2_Logpoint_100.72.36.70",
    protocol="object-group",
    service="Windows_Logging",
    router="RGDCPe1",
    vrf="CS",
    route_destination="100.72.36.70"
)

print()
print("Trace Packet")
print("=" * 60)

if not result:
    print("No result")
else:
    print("Network hops:", len(result.network_hops))

    for hop in result.network_hops:
        print()
        print("Hop      :", hop.hop_number)
        print("Type     :", hop.hop_type)
        print("Device   :", hop.device)
        print("Context  :", hop.context)
        print("VRF      :", hop.vrf)
        print("Ingress  :", hop.ingress_interface)
        print("Egress   :", hop.egress_interface)
        print("Route    :", hop.route)
        print("NextHop  :", hop.next_hop)
        print("Reason   :", hop.reason)

    print()
print("Explanation")
print("-" * 60)

explanation = result.explanation

if hasattr(explanation, "messages"):
    for line in explanation.messages:
        print(line)
elif hasattr(explanation, "lines"):
    for line in explanation.lines:
        print(line)
else:
    print(explanation)