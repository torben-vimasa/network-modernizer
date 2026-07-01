class TopologyTraversalEngine:

    def __init__(self, graph):
        self.graph = graph

    def find_connected_device(self, context, interface_name):

        asa_interface = self._find_asa_interface(context, interface_name)

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

            vrf = self._find_interface_vrf(neighbor)

            return {
                "found": True,
                "method": "connected_to",
                "context": context,
                "interface": asa_interface.properties.get("interface") or interface_name,
                "connected_interface": neighbor.name,
                "connected_vrf": vrf,
                "router": router.name,
                "reason": f"{asa_interface.name} is connected to {router.name}:{neighbor.name}"
            }

        return {
            "found": False,
            "reason": f"No connected router found for {asa_interface.name}"
        }

    def _find_asa_interface(self, context, interface_name):

        exact = self.graph.find(
            "ASAInterface",
            f"{context}:{interface_name}"
        )

        if exact:
            return exact

        wanted = f"{context}:{interface_name}".lower()

        for node in self.graph.nodes.values():

            if node.type != "ASAInterface":
                continue

            if node.name.lower() == wanted:
                return node

        return None

    def _find_parent_router(self, interface_node):

        for relation, neighbor in self.graph.neighbors(interface_node.id):

            if relation == "HAS_INTERFACE" and neighbor.type == "Router":
                return neighbor

        return None

    def _find_interface_vrf(self, interface_node):

        vrf = interface_node.properties.get("vrf")

        if vrf:
            return vrf

        for relation, neighbor in self.graph.neighbors(interface_node.id):

            if relation == "BELONGS_TO_VRF" and neighbor.type == "VRF":
                return neighbor.name

        return None