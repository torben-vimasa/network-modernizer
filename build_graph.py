import json
from pathlib import Path

from graph.graph import KnowledgeGraph

output_dir = Path("output")

with open(output_dir / "vrf_inventory.json", "r") as f:
    vrfs = json.load(f)

graph = KnowledgeGraph()

for vrf_name, vrf in vrfs.items():

    vrf_node = graph.add_node(
        "VRF",
        vrf_name,
        {
            "complexity_score": vrf["complexity_score"],
            "link_count": vrf["link_count"]
        }
    )

    # Contexts
    for context in vrf["contexts"]:
        context_node = graph.add_node("Context", context)
        graph.add_relationship(context_node, vrf_node, "USES_VRF")

    # ASA Interfaces
    for interface in vrf["asa_interfaces"]:
        interface_node = graph.add_node("ASAInterface", interface)
        graph.add_relationship(interface_node, vrf_node, "BELONGS_TO_VRF")

    # ACL / Access Groups
    for acl in vrf["access_groups"]:
        acl_node = graph.add_node("ACL", acl)
        graph.add_relationship(acl_node, vrf_node, "PROTECTS")

    # Routers
    for router in vrf["routers"]:
        router_node = graph.add_node("Router", router)
        graph.add_relationship(router_node, vrf_node, "HOSTS_VRF")

graph.export_json(output_dir / "knowledge_graph.json")

print("Knowledge Graph")
print("----------------")
print(f"Nodes: {len(graph.nodes)}")
print(f"Relationships: {len(graph.relationships)}")
print("Output: output/knowledge_graph.json")
