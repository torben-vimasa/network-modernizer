class DependencyEngine:
    def __init__(self, graph):
        self.graph = graph

    def collect(self, node_type, name, depth=2):
        start_node = self.graph.find(node_type, name)

        if not start_node:
            return None

        visited = set()
        results = []

        self._walk(
            node=start_node,
            depth=depth,
            visited=visited,
            results=results,
            level=0,
            via_relation=None
        )

        return {
            "start": start_node,
            "dependencies": results
        }

    def _walk(self, node, depth, visited, results, level, via_relation):
        if depth < 0:
            return

        if node.id in visited:
            return

        visited.add(node.id)

        results.append({
            "level": level,
            "relation": via_relation,
            "node": node
        })

        for relation, neighbor in self.graph.neighbors(node.id):
            self._walk(
                node=neighbor,
                depth=depth - 1,
                visited=visited,
                results=results,
                level=level + 1,
                via_relation=relation
            )