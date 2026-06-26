from builders.graph_builder import GraphBuilder
from engines.security_engine import SecurityEngine


graph = GraphBuilder().build_from_vrf_inventory()
engine = SecurityEngine(graph)

tests = [
    {
        "name": "Direct host/object match",
        "source": "172.27.210.20",
        "destination": "SPNS2_Logpoint_100.72.36.70",
        "protocol": "object-group",
        "service": "Windows_Logging",
    },
    {
        "name": "ObjectGroup destination match",
        "source": "PoC_CS-VRF_Source_Host",
        "destination": "172.21.255.2",
        "protocol": "tcp",
        "service": "ssh",
    },
]

print()
print("Security Engine Test")
print("=" * 40)

for test in tests:
    print()
    print(test["name"])
    print("-" * 40)

    result = engine.is_permitted(
        test["source"],
        test["destination"],
        protocol=test["protocol"],
        service=test["service"]
    )

    print(result.reason)

    if result.rule:
        print(result.rule.properties["action"])
        print(result.rule.properties["raw"])