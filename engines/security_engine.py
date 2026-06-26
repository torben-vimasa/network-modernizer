from graph.graph import KnowledgeGraph


class SecurityEngine:

    def __init__(self, graph: KnowledgeGraph):
        self.graph = graph

    def is_permitted(self, source, destination):

        matches = []

        for node in self.graph.nodes.values():

            if node.type != "ACLRule":
                continue

            src = node.properties.get("source_value")
            dst = node.properties.get("destination_value")

            if src == source and dst == destination:
                matches.append(node)

        return matches