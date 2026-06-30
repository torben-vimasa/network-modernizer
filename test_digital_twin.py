from api.digital_twin import DigitalTwin


dt = DigitalTwin()

from models.route_entry import RouteEntry

dt.firewall_routes = [
    RouteEntry(
        router="BHASA1",
        vrf="BDK-Mgmt",
        prefix="100.72.36.64/27",
        next_hop="172.21.2.26",
        protocol="static"
    )
]

dt.firewall_interfaces = [
    {
        "name": "CS",
        "subnet": "10.255.255.16/28"
    },
    {
        "name": "Transit",
        "subnet": "172.21.2.16/28"
    }
]

result = dt.trace.trace(
source="172.27.210.20",
destination="SPNS2_Logpoint_100.72.36.70",
protocol="object-group",
service="Windows_Logging",
router="RGDCPe1",
vrf="CS",
route_destination="100.72.36.70"
)

print()
print("TRACE")
print("=" * 60)

print()
print("SECURITY")
print("------------------------")
print(result.security.reason)


if result.security.match:
    print("Firewall :", result.security.match.firewall)
    print("Context  :", result.security.match.context)
    print("Interface:", result.security.match.interface)
    print("ACL      :", result.security.match.acl)
    print("Rule     :", result.security.match.rule)
    print("Action   :", result.security.match.action)

print()
print("HOPS")
print("------------------------")

if result.hops:
    for index, hop in enumerate(result.hops, start=1):
        print(f"Hop {index}")
        print("Router   :", hop.router)
        print("VRF      :", hop.vrf)
        print("Route    :", hop.route)
        print("Next Hop :", hop.next_hop)
        print()
else:
    print("No hops")

print("FIREWALL HOPS")
print("------------------------")

if result.firewall_hops:
    for fw_hop in result.firewall_hops:
        print("Firewall :", fw_hop.firewall)
        print("Context  :", fw_hop.context)
        print("Ingress  :", fw_hop.ingress_interface)
        print("IP       :", fw_hop.ip)
        print("Subnet   :", fw_hop.subnet)
        print()
else:
    print("No firewall hops")
    print()

print("NETWORK HOPS")
print("------------------------")

if result.network_hops:
    for hop in result.network_hops:
        print("Hop      :", hop.hop_number)
        print("Type     :", hop.hop_type)
        print("Device   :", hop.device)
        print("Context  :", hop.context)
        print("VRF      :", hop.vrf)
        print("Ingress  :", hop.ingress_interface)
        print("Egress   :", hop.egress_interface)
        print("IP       :", hop.ip)
        print("Subnet   :", hop.subnet)
        print("Route    :", hop.route)
        print("Next Hop :", hop.next_hop)
        print("Reason   :", hop.reason)
        print()
else:
    print("No network hops")
    print()

print("EXPLANATION")
print("------------------------")



if result.explanation:
    for step in result.explanation.steps:
        print(step)