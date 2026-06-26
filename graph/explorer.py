from graph.dependencies import DependencyEngine

class Explorer:

    def __init__(self, graph):
        self.graph = graph

    def explore(self, node_type, name):

        node = self.graph.find(node_type, name)

        if not node:
            print(f"{node_type} '{name}' not found")
            return

        print()
        print("=" * 60)
        print(f"{node.type}: {node.name}")
        print("=" * 60)

        if node.properties:
            print("\nProperties")
            print("-" * 20)

            for key, value in node.properties.items():
                print(f"{key:20} {value}")

        grouped = {}

        for relation, neighbor in self.graph.neighbors(node.id):

            grouped.setdefault(neighbor.type, [])

            grouped[neighbor.type].append(
                (
                    relation,
                    neighbor
                )
            )

        print("\nRelationships")
        print("-" * 20)

        for neighbor_type in sorted(grouped):

            print(f"\n{neighbor_type}")

            print("-" * len(neighbor_type))

            for relation, neighbor in grouped[neighbor_type]:

                print(
                    f"{relation:20} {neighbor.name}"
                )
    def dependencies(self, node_type, name, depth=2):
        engine = DependencyEngine(self.graph)
        result = engine.collect(node_type, name, depth)

        if not result:
            print(f"{node_type} '{name}' not found")
            return

        print()
        print("=" * 60)
        print(f"DEPENDENCIES: {node_type} {name}")
        print("=" * 60)

        for item in result["dependencies"]:
            indent = "  " * item["level"]
            relation = item["relation"]
            node = item["node"]

            if relation:
                print(f"{indent}{relation} -> {node.type}: {node.name}")
            else:
                print(f"{indent}{node.type}: {node.name}")
    
    def explore_acl(self, name):
        self.explore("ACL", name)

    def explore_acl_rule(self, name):
        self.explore("ACLRule", name)
