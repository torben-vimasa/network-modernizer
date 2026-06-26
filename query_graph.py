import json
from pathlib import Path
from builders.graph_builder import GraphBuilder
from graph.explorer import Explorer
from graph.path_engine import PathEngine



def main():
    graph = GraphBuilder().build_from_vrf_inventory()
    explorer = Explorer(graph)
    path = PathEngine(graph)
    

    print("Knowledge Graph Query")
    print("---------------------")
    print(f"Nodes: {len(graph.nodes)}")
    print(f"Relationships: {len(graph.relationships)}")

    explorer.explore("VRF", "bane1")
    explorer.explore("VRF", "signal-program")
    explorer.explore("VRF", "Internet")

    explorer.explore("ASAInterface", "BDK-Mgmt:Bane1")
    explorer.explore("ASAInterface", "Site2Site-VPN:inside")
    explorer.explore("ASAInterface", "BDK-Teknik:inside")
   
    
    explorer.dependencies("VRF", "bane1", depth=2)
    explorer.dependencies("ASAInterface", "BDK-Mgmt:Bane1", depth=2)
    path.explain_ip("10.255.255.33", "10.255.255.36")
    path.explain_ip("172.27.2.100", "172.27.57.5")
    result = path.analyze_ip_path("172.27.2.100", "172.27.57.5")

    output_file = Path("output/path_analysis.json")

    result = path.analyze_ip_path("172.27.2.100", "172.27.57.5")

    clean_result = {
        "source_ip": result.source_ip,
        "destination_ip": result.destination_ip,
        "source_matches": [
            {
                "node_type": item["node"].type,
                "node_name": item["node"].name,
                "network": item["network"],
                "vrf": item["vrf"]
            }
            for item in result.source_matches
        ],
        "destination_matches": [
            {
                "node_type": item["node"].type,
                "node_name": item["node"].name,
                "network": item["network"],
                "vrf": item["vrf"]
            }
            for item in result.destination_matches
        ],
        "vrfs": result.vrfs,
        "firewalls": result.firewalls,
        "routers": result.routers,
        "findings": result.findings,
        "warnings": result.warnings,
        "confidence": result.confidence
    }

    with open(output_file, "w") as f:
        json.dump(clean_result, f, indent=4)

    print("Output gemt: output/path_analysis.json")

    explorer.explore_acl("access-in-bane1")
    explorer.explore_acl_rule("access-in-bane1:1")
    explorer.explore("ObjectGroup", "BDK-Mgmt:GSMR_ALL_HOSTS")
    explorer.explore("ObjectGroup", "BDK-Teknik:GSMR_SSH_HOSTS")
    explorer.explore_acl_rule("access-in-bane1:467")
    explorer.explore_acl_rule("access-in-bane1:468")
    explorer.explore_acl_rule("access-in-bane1:469")
    explorer.explore_acl_rule("access-in-cs:513")

if __name__ == "__main__":
    main()

    