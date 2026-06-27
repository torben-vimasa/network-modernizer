from builders.graph_builder import GraphBuilder

graph = GraphBuilder().build_from_vrf_inventory()

print()
print("Router Graph Test")
print("=" * 50)

routers = graph.find_by_type("Router")
interfaces = graph.find_by_type("Interface")
ips = graph.find_by_type("IPAddress")
subnets = graph.find_by_type("Subnet")

print(f"Routers    : {len(routers)}")
print(f"Interfaces : {len(interfaces)}")
print(f"IP nodes   : {len(ips)}")
print(f"Subnets    : {len(subnets)}")

print()

router = routers[0]
print(router.name)

router_id = router.id

for relation, neighbor in graph.neighbors(router_id):
    if relation == "HAS_INTERFACE":
        print(
            neighbor.name,
            neighbor.properties.get("vrf"),
            neighbor.properties.get("description")
        )