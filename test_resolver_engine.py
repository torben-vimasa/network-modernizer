from builders.graph_builder import GraphBuilder
from engines.resolver_engine import ResolverEngine


graph = GraphBuilder().build_from_vrf_inventory()
resolver = ResolverEngine(graph)

tests = [
    "10.255.255.17",
    "172.27.133.2",
]

print()
print("Resolver Engine Test")
print("=" * 50)

for ip in tests:
    result = resolver.resolve_ip(ip)

    print()
    print(ip)
    print("-" * 50)
    print("Resolved   :", result["resolved"])
    print("Confidence :", result["confidence"])
    print("Method     :", result["method"])
    print("Reason     :", result["reason"])

    if result.get("router"):
        print("Router     :", result["router"])
        print("VRF        :", result["vrf"])
        print("Interface  :", result["interface"])

    if result["references"]:
        print("References :")
        for ref in result["references"][:5]:
            print(
                f'  {ref["router"]} VRF={ref["vrf"]} '
                f'{ref["prefix"]} via {ip}'
            )