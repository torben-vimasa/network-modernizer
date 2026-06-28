from builders.graph_builder import GraphBuilder

graph = GraphBuilder().build_from_vrf_inventory()

acl = graph.find("ACL", "access-in-bane1")

print()
print("ACL neighbors")
print("=" * 40)

for rel, node in graph.neighbors(acl.id):
    print(rel, node.type, node.name)

print()
print("Context neighbors")
print("=" * 40)

ctx = graph.find("Context", "BDK-Mgmt")

for rel, node in graph.neighbors(ctx.id):
    print(rel, node.type, node.name)