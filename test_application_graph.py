from builders.graph_builder import GraphBuilder

graph = GraphBuilder().build_from_vrf_inventory()

print()
print("Applications")
print("=" * 50)

for app in graph.find_by_type("Application"):

    print(app.name)

    for rel, node in graph.neighbors(app.id):
        print(" ", rel, node.type, node.name)