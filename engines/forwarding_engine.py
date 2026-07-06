import ipaddress


class ForwardingEngine:

    def __init__(self, graph):
        self.graph = graph

    def candidates_for_next_hop(
        self,
        next_hop,
        exclude_device=None
    ):

        subnet = self._find_subnet_for_ip(next_hop)

        if not subnet:
            return {
                "found": False,
                "reason": f"No subnet found for next-hop {next_hop}",
                "candidates": []
            }

        candidates = []

        for relation, neighbor in self.graph.neighbors(subnet.id):

            if relation != "IN_SUBNET":
                continue

            if neighbor.type not in ["RouterInterface", "ASAInterface", "Interface"]:
                continue

            device = self._find_parent_device(neighbor)

            if not device:
                continue

            if exclude_device and device.name == exclude_device:
                continue

            candidates.append(
                {
                    "device": device.name,
                    "device_type": device.type,
                    "interface": neighbor.name,
                    "interface_type": neighbor.type,
                    "subnet": subnet.name,
                    "ip": neighbor.properties.get("ip"),
                    "reason": f"{neighbor.name} is in subnet {subnet.name}"
                }
            )

        return {
            "found": bool(candidates),
            "subnet": subnet.name,
            "candidates": candidates
        }

    def _find_subnet_for_ip(self, ip):

        address = ipaddress.ip_address(ip)

        for node in self.graph.nodes.values():

            if node.type != "Subnet":
                continue

            prefix = node.properties.get("prefix") or node.name

            try:
                network = ipaddress.ip_network(prefix, strict=False)
            except ValueError:
                continue

            if address in network:
                return node

        return None

    def _find_parent_device(self, interface_node):

        for relation, neighbor in self.graph.neighbors(interface_node.id):

            if relation != "HAS_INTERFACE":
                continue

            if neighbor.type in ["Router", "Firewall", "Switch"]:
                return neighbor

        return None