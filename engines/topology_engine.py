class TopologyEngine:

    def __init__(self, graph):
        self.graph = graph

    def resolve_router(self, next_hop):
        ip_node = self.graph.find("IPAddress", next_hop)

        if not ip_node:
            return None

        for relation, interface in self.graph.neighbors(ip_node.id):
            if relation != "HAS_IP":
                continue

            for rel2, router in self.graph.neighbors(interface.id):
                if rel2 == "HAS_INTERFACE" and router.type == "Router":
                    return {
                        "router": router.name,
                        "vrf": interface.properties.get("vrf"),
                        "interface": interface.name,
                        "ip": next_hop
                    }

        return None