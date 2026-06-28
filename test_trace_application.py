from api.digital_twin import DigitalTwin

dt = DigitalTwin()

result = dt.trace_application(
    application="KMS",
    router="RGDCPe1",
    vrf="CS",
    route_destination="100.72.36.70"
)

print()
print("APPLICATION TRACE")
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

print()

print("HOPS")
print("------------------------")

for i, hop in enumerate(result.hops, start=1):
    print(f"Hop {i}")
    print("Router   :", hop.router)
    print("VRF      :", hop.vrf)
    print("Route    :", hop.route)
    print("Next Hop :", hop.next_hop)
    print()

print("EXPLANATION")
print("------------------------")

for step in result.explanation.steps:
    print(step)