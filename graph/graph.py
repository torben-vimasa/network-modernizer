import json
from graph.nodes import Node
from graph.relationships import Relationship


class KnowledgeGraph:
    def __init__(self):
        self.nodes = {}
        self.relationships = []

    def add_node(self, node_type, name, properties=None):
        node_id = f"{node_type}:{name}"

        if node_id not in self.nodes:
            self.nodes[node_id] = Node(
                id=node_id,
                type=node_type,
                name=name,
                properties=properties or {}
            )

        return node_id

    def add_relationship(self, source, target, rel_type, properties=None):
        self.relationships.append(
            Relationship(
                source=source,
                target=target,
                type=rel_type,
                properties=properties or {}
            )
        )

    def find(self, node_type, name):
        return self.nodes.get(f"{node_type}:{name}")

    def find_by_type(self, node_type):
        return [
            node
            for node in self.nodes.values()
            if node.type == node_type
        ]

    def neighbors(self, node_id):
        result = []

        for rel in self.relationships:
            if rel.source == node_id:
                result.append((rel.type, self.nodes[rel.target]))

            elif rel.target == node_id:
                result.append((rel.type, self.nodes[rel.source]))

        return result

    def export_json(self, output_file):
        data = {
            "nodes": [node.__dict__ for node in self.nodes.values()],
            "relationships": [rel.__dict__ for rel in self.relationships]
        }

        with open(output_file, "w") as f:
            json.dump(data, f, indent=4)