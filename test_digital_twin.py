from api.digital_twin import DigitalTwin


dt = DigitalTwin()

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

print()

print("ROUTE")
print("------------------------")

if result.route and result.route.matched:

    print("Router   :", result.route.hop.router)
    print("VRF      :", result.route.hop.vrf)
    print("Route    :", result.route.hop.route)
    print("Next Hop :", result.route.hop.next_hop)

else:

    print("No route")