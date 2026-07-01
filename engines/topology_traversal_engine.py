class TopologyTraversalEngine:

    def __init__(self, graph):
        self.graph = graph

    def find_connected_device(
        self,
        context,
        interface_name
    ):

        asa_interface = self.graph.find(
            "ASAInterface",
            f"{context}:{interface_name}"
        )

        if not asa_interface:
            return {
                "found": False,
                "reason": f"ASA interface {context}:{interface_name} not found in graph"
            }

        for relation, neighbor in self.graph.neighbors(asa_interface.id):

            if relation != "CONNECTED_TO":
                continue

            if neighbor.type not in ["RouterInterface", "Interface"]:
                continue

            router = self._find_parent_router(neighbor)

            if not router:
                continue

            return {
                "found": True,
                "method": "connected_to",
                "context": context,
                "interface": interface_name,
                "connected_interface": neighbor.name,
                "router": router.name,
                "reason": f"{context}:{interface_name} is connected to {router.name}:{neighbor.name}"
            }

        return {
            "found": False,
            "reason": f"No connected router found for {context}:{interface_name}"
        }

    def _find_parent_router(self, interface_node):

        for relation, neighbor in self.graph.neighbors(interface_node.id):

            if relation == "HAS_INTERFACE" and neighbor.type == "Router":
                return neighbor

        return None