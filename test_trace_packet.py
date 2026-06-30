from api.digital_twin import DigitalTwin
from models.route_entry import RouteEntry
from reporters.trace_reporter import TraceReporter


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

TraceReporter(result).print_console()