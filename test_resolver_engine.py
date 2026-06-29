from builders.graph_builder import GraphBuilder
from engines.resolver_engine import ResolverEngine


graph = GraphBuilder().build_from_vrf_inventory()
resolver = ResolverEngine(graph)

for ip in [
    "10.255.255.17",
    "172.27.133.2",
]:
    result = resolver.resolve_ip(ip)

    print()
    print(ip)
    print("-" * 50)
    print("Resolved  :", result["resolved"])
    print("Confidence:", result["confidence"])
    print("Method    :", result["method"])
    print("Reason    :", result["reason"])

    if result["method"] == "asa_interface":
        print("Firewall  :", result["firewall"])
        print("Context   :", result["context"])
        print("Interface :", result["interface"])
        print("Subnet    :", result["subnet"])

    if result["method"] == "router_inventory":
        print("Router    :", result["router"])
        print("VRF       :", result["vrf"])
        print("Interface :", result["interface"])