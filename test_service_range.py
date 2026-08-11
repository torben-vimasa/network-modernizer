from api.digital_twin import DigitalTwin

twin = DigitalTwin()

rule = twin.graph.find(
    "ACLRule",
    "access-in-cs:12009"
)

for service in ["22", "7937", "9000", "9936", "9937"]:
    matched = twin.security._service_matches(
        rule,
        service
    )

    print(
        f"{service:>5} -> "
        f"{'MATCH' if matched else 'NO MATCH'}"
    )