from builders.graph_builder import GraphBuilder
from engines.security_engine import SecurityEngine


graph = GraphBuilder().build_from_vrf_inventory()
engine = SecurityEngine(graph)

rule = engine.is_permitted(
    "172.27.210.20",
    "SPNS2_Logpoint_100.72.36.70"
)

print()
print("Security Engine Test")
print("=" * 40)

if rule:
    print(rule.name)
    print(rule.properties["action"])
    print(rule.properties["raw"])
else:
    print("No match")