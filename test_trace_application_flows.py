from api.digital_twin import DigitalTwin

dt = DigitalTwin()

result = dt.trace_application_flows(
    application="KMS",
    router="RGDCPe1",
    vrf="CS",
    route_destination="100.72.36.70"
)

print()
print("APPLICATION TRACE")
print("=" * 60)

print()
print("Application :", result.application)
print("Criticality :", result.criticality)
print("Max outage  :", result.max_outage_minutes, "minutes")

print()
print("Flows :", len(result.traces))

for index, trace in enumerate(result.traces, start=1):

    print()
    print(f"FLOW {index}")
    print("-" * 40)

    print(trace.security.reason)

    for hop in trace.hops:
        print("Route   :", hop.route)
        print("Next hop:", hop.next_hop)

    print()

    for step in trace.explanation.steps:
        print(step)