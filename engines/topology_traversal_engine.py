from models.traversal_target import TraversalTarget


class TopologyTraversalEngine:

    def __init__(self, graph):
        self.graph = graph

    def find_connected_device(self, context, interface_name):

        interface = self._find_interface(
            context,
            interface_name
        )

        if not interface:
            return {
                "found": False,
                "reason": f"Interface {context}:{interface_name} not found in graph"
            }

        for relation, neighbor in self.graph.neighbors(interface.id):

            if relation != "CONNECTED_TO":
                continue

            device = self._find_parent_device(neighbor)

            if not device:
                continue

            vrf = self._find_interface_vrf(neighbor)

            reason = (
                f"{interface.name} is connected to "
                f"{device.name}:{neighbor.name}"
            )

            target = TraversalTarget(
                device_name=device.name,
                device_type=device.type,
                interface=neighbor.name,
                vrf=vrf,
                method="topology_connected_to",
                confidence="high",
                reason=reason
            )

            return {
                "found": True,
                "method": "connected_to",
                "context": context,
                "interface": interface.properties.get("interface") or interface_name,
                "connected_interface": neighbor.name,
                "connected_vrf": vrf,
                "device": device.name,
                "device_type": device.type,
                "router": device.name if device.type == "Router" else None,
                "target": target,
                "reason": reason
            }

        return {
            "found": False,
            "reason": f"No connected device found for {interface.name}"
        }

    def _find_interface(self, context, interface_name):

        candidates = [
            ("ASAInterface", f"{context}:{interface_name}"),
            ("RouterInterface", f"{context}:{interface_name}"),
            ("Interface", f"{context}:{interface_name}"),
        ]

        for node_type, name in candidates:
            exact = self.graph.find(node_type, name)
            if exact:
                return exact

        wanted = f"{context}:{interface_name}".lower()

        for node in self.graph.nodes.values():

            if node.type not in ["ASAInterface", "RouterInterface", "Interface"]:
                continue

            if node.name.lower() == wanted:
                return node

        return None

    def _find_parent_device(self, interface_node):

        for relation, neighbor in self.graph.neighbors(interface_node.id):

            if relation != "HAS_INTERFACE":
                continue

            if neighbor.type in ["Router", "Firewall", "Switch"]:
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