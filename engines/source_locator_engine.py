import ipaddress


class SourceLocatorEngine:

    def __init__(self, graph):
        self.graph = graph

    def locate(self, source_ip):

        exact = self._locate_exact_ip(source_ip)

        if exact:
            return exact

        subnet = self._locate_by_subnet(source_ip)

        if subnet:
            return subnet

        return {
            "found": False,
            "source": source_ip,
            "reason": "Source IP was not found in graph inventory",
            "confidence": "low"
        }

    def _locate_exact_ip(self, source_ip):

        ip_node = self.graph.find("IPAddress", source_ip)

        if not ip_node:
            return None

        for relation, interface in self.graph.neighbors(ip_node.id):

            if relation != "HAS_IP":
                continue

            for rel2, device in self.graph.neighbors(interface.id):

                if rel2 == "HAS_INTERFACE":

                    return {
                        "found": True,
                        "source": source_ip,
                        "method": "exact_ip",
                        "device": device.name,
                        "device_type": device.type,
                        "interface": interface.properties.get("name") or interface.name,
                        "vrf": interface.properties.get("vrf"),
                        "subnet": interface.properties.get("subnet"),
                        "confidence": "high",
                        "reason": f"Source IP found directly on interface {interface.name}"
                    }

        return None

    def _locate_by_subnet(self, source_ip):

        ip = ipaddress.ip_address(source_ip)

        for node in self.graph.nodes.values():

            if node.type not in ["Interface", "ASAInterface"]:
                continue

            subnet = node.properties.get("subnet")

            if not subnet:
                continue

            try:
                network = ipaddress.ip_network(subnet, strict=False)
            except ValueError:
                continue

            if ip not in network:
                continue

            device = None

            for relation, neighbor in self.graph.neighbors(node.id):

                if relation == "HAS_INTERFACE":
                    device = neighbor
                    break

            return {
                "found": True,
                "source": source_ip,
                "method": "subnet_match",
                "device": device.name if device else node.properties.get("device"),
                "device_type": device.type if device else node.type,
                "interface": node.properties.get("name") or node.name,
                "vrf": node.properties.get("vrf"),
                "subnet": subnet,
                "confidence": "medium",
                "reason": f"Source IP belongs to subnet {subnet}"
            }

        return None