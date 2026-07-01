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
        protocol="static",
        exit_interface="SPNS2-TRANSIT-JTTN"
    ),
    RouteEntry(
        router="BHASA1",
        vrf="BDK-Mgmt",
        prefix="0.0.0.0/0",
        next_hop="10.255.255.161",
        protocol="static",
        exit_interface="SPNS2-TRANSIT-JTTN"
    )
]

dt.firewall_routes[0].ingress_interface = "CS"
dt.firewall_routes[1].ingress_interface = "SPNS2-TRANSIT-JTTN"

result = dt.trace.trace(
    source="172.27.210.20",
    destination="SPNS2_Logpoint_100.72.36.70",
    protocol="object-group",
    service="Windows_Logging",
    router="RGDCPe1",
    vrf="CS",
    route_destination="100.72.36.70",
    max_hops=4,
    stop_on_destination=False
)

TraceReporter(result).print_console()