from pathlib import Path

from graph.graph import KnowledgeGraph
from builders.bgp_builder import BGPBuilder
from parsers.bgp_parser import BGPParser

graph = KnowledgeGraph()

with open(
    Path("data/router_raw/OBvDCPe1-20260424.txt"),
    encoding="utf-8",
    errors="ignore"
) as f:

    routes = BGPParser().parse(
        f.readlines(),
        source_router="OBvDCPe1",
        vrf="default"
    )

builder = BGPBuilder(graph)

builder.add_routes(routes)

print()
print("BGP Builder")
print("=" * 50)

print("Routes :", len(routes))
print("Graph nodes :", len(graph.nodes))

count = 0

for node in graph.nodes.values():

    if node.type == "Prefix":

        print(node.name, node.properties)

        count += 1

        if count >= 10:
            break