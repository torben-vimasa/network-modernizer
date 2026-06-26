from builders.graph_builder import GraphBuilder

graph = GraphBuilder().build_from_vrf_inventory()

search_text = "PoC_Destination_Hosts"

print(f"Searching for: {search_text}")
print("-" * 60)

for node in graph.nodes.values():
    if node.type != "ACLRule":
        continue

    raw = node.properties.get("raw") or ""

    if search_text in raw:
        print(node.name)
        print(raw)
        print()