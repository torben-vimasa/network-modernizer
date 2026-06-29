from graph.graph import KnowledgeGraph

from builders.import_builder import ImportBuilder
from importers.router_importer import RouterImporter

graph = KnowledgeGraph()

result = RouterImporter().import_router(
    "data/router_raw/OBvDCPe1-20260424.txt"
)

ImportBuilder(graph).build(result)

print()
print("Unified Import Builder")
print("=" * 60)

print("Nodes         :", len(graph.nodes))
print("Relationships :", len(graph.relationships))

print()

for node in list(graph.nodes.values())[:10]:
    print(node.type, node.name)