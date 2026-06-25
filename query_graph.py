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

if __name__ == "__main__":
    main()