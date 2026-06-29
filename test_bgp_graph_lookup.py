from pathlib import Path

from builders.bgp_builder import BGPBuilder
from engines.bgp_engine import BGPEngine
from graph.graph import KnowledgeGraph
from parsers.bgp_parser import BGPParser


file = Path("data/router_raw/OBvDCPe1-20260424.txt")

with open(file, encoding="utf-8", errors="ignore") as f:
    routes = BGPParser().parse(
        f.readlines(),
        source_router=file.stem,
        vrf="unknown"
    )

graph = KnowledgeGraph()
BGPBuilder(graph).add_routes(routes)

prefix_nodes = graph.find_by_type("Prefix")

engine = BGPEngine(routes)
result = engine.lookup(
    destination="10.30.9.152",
    vrf="unknown"
)

print()
print("BGP Graph Lookup")
print("=" * 50)

print("Routes parsed :", len(routes))
print("Prefix nodes  :", len(prefix_nodes))
print("Matched       :", result.matched)

if result.route:
    print("Prefix        :", result.route.prefix)
    print("NextHop       :", result.route.next_hop)
    print("Router        :", result.route.source_router)