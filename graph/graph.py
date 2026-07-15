import json
from collections import defaultdict

from graph.nodes import Node
from graph.relationships import Relationship


class KnowledgeGraph:
    def __init__(self):
        self.nodes = {}
        self.relationships = []

        # node_id -> [(relationship_type, neighbor_node_id), ...]
        self._adjacency = defaultdict(list)

        # node_type -> [node_id, ...]
        self._nodes_by_type = defaultdict(list)

    def add_node(self, node_type, name, properties=None):
        node_id = f"{node_type}:{name}"

        if node_id not in self.nodes:
            self.nodes[node_id] = Node(
                id=node_id,
                type=node_type,
                name=name,
                properties=properties or {}
            )

            self._nodes_by_type[node_type].append(node_id)

        return node_id

    def add_relationship(
        self,
        source,
        target,
        rel_type,
        properties=None
    ):
        relationship = Relationship(
            source=source,
            target=target,
            type=rel_type,
            properties=properties or {}
        )

        self.relationships.append(relationship)

        # Preserve the old undirected neighbors() behavior.
        self._adjacency[source].append((rel_type, target))
        self._adjacency[target].append((rel_type, source))

    def find(self, node_type, name):
        return self.nodes.get(f"{node_type}:{name}")

    def find_by_type(self, node_type):
        return [
            self.nodes[node_id]
            for node_id in self._nodes_by_type.get(node_type, [])
            if node_id in self.nodes
        ]

    def neighbors(self, node_id):
        return [
            (relationship_type, self.nodes[neighbor_id])
            for relationship_type, neighbor_id
            in self._adjacency.get(node_id, [])
            if neighbor_id in self.nodes
        ]

    def rebuild_indexes(self):
        """Rebuild indexes after direct manipulation or deserialization."""

        self._adjacency = defaultdict(list)
        self._nodes_by_type = defaultdict(list)

        for node_id, node in self.nodes.items():
            self._nodes_by_type[node.type].append(node_id)

        for relationship in self.relationships:
            self._adjacency[relationship.source].append(
                (relationship.type, relationship.target)
            )
            self._adjacency[relationship.target].append(
                (relationship.type, relationship.source)
            )

    def export_json(self, output_file):
        data = {
            "nodes": [
                node.__dict__
                for node in self.nodes.values()
            ],
            "relationships": [
                relationship.__dict__
                for relationship in self.relationships
            ]
        }

        with open(
            output_file,
            "w",
            encoding="utf-8"
        ) as handle:
            json.dump(data, handle, indent=4)
