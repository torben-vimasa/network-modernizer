from api.digital_twin import DigitalTwin

twin = DigitalTwin()

tests = [
    ("tcp", "88"),
    ("tcp", "ldap"),
    ("tcp", "445"),
    ("tcp", "50000"),
    ("tcp", "22"),
    ("udp", "88"),
    ("udp", "ldap"),
    ("udp", "ntp"),
]

for protocol, service in tests:
    result = twin.security._service_object_group_matches(
        "Nokia_Jump_Ports",
        protocol,
        service
    )

    print(
        f"{protocol:>3}/{service:<6} -> "
        f"{'MATCH' if result else 'NO MATCH'}"
    )