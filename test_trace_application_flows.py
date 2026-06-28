from api.digital_twin import DigitalTwin

dt = DigitalTwin()

results = dt.trace_application_flows(
    application="KMS",
    router="RGDCPe1",
    vrf="CS",
    route_destination="100.72.36.70"
)

print()
print("APPLICATION FLOW TRACES")
print("=" * 60)

print("Flows:", len(results))

for index, result in enumerate(results, start=1):

    print()
    print(f"FLOW {index}")
    print("-" * 40)

    print(result.security.reason)

    for hop in result.hops:
        print("Route   :", hop.route)
        print("Next hop:", hop.next_hop)

    print()

    for step in result.explanation.steps:
        print(step)