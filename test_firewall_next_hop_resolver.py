from api.digital_twin import DigitalTwin
from engines.resolver_engine import ResolverEngine


dt = DigitalTwin()

neighbor_map = {
    "172.21.2.26": {
        "router": "OBvDCPe1",
        "vrf": "CS",
        "interface": "Transit",
        "confidence": "manual",
        "reason": "Known firewall transit next-hop toward OBV"
    }
}

resolver = ResolverEngine(
    dt.graph,
    neighbor_map=neighbor_map
)

result = resolver.resolve_ip("172.21.2.26")

print()
print("Firewall Next-Hop Resolver")
print("=" * 60)

print("Resolved  :", result.get("resolved"))
print("Method    :", result.get("method"))
print("Router    :", result.get("router"))
print("VRF       :", result.get("vrf"))
print("Interface :", result.get("interface"))
print("Reason    :", result.get("reason"))
print("Confidence:", result.get("confidence"))

print()
print(result)