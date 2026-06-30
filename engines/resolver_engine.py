import json
from pathlib import Path


class ResolverEngine:

    def __init__(
        self,
        graph,
        routes_file=Path("output/routes.json"),
        neighbor_map=None
    ):
        self.graph = graph
        self.neighbor_map = neighbor_map or {}

        with open(routes_file, "r") as f:
            self.routes = json.load(f)

    def resolve_ip(self, ip):

        direct = self._resolve_from_router_inventory(ip)

        if direct:
            return direct

        mapped = self._resolve_from_neighbor_map(ip)

        if mapped:
            return mapped

        asa = self._resolve_from_asa_interface(ip)

        if asa:
            return asa

        references = self._find_route_references(ip)

        if references:
            return {
                "resolved": False,
                "ip": ip,
                "confidence": "medium",
                "method": "route_reference",
                "reason": f"IP is used as next-hop by {len(references)} route entries",
                "references": references[:10],
            }

        return {
            "resolved": False,
            "ip": ip,
            "confidence": "low",
            "method": "unknown",
            "reason": "IP was not found in graph or route references",
            "references": [],
        }

    def _resolve_from_router_inventory(self, ip):
        ip_node = self.graph.find("IPAddress", ip)

        if not ip_node:
            return None

        for relation, interface in self.graph.neighbors(ip_node.id):

            if relation != "HAS_IP":
                continue

            if interface.type != "Interface":
                continue

            for rel2, router in self.graph.neighbors(interface.id):

                if rel2 == "HAS_INTERFACE" and router.type == "Router":

                    return {
                        "resolved": True,
                        "ip": ip,
                        "confidence": "high",
                        "method": "router_inventory",
                        "router": router.name,
                        "vrf": interface.properties.get("vrf"),
                        "interface": interface.properties.get("name") or interface.name,
                        "subnet": interface.properties.get("subnet"),
                        "reason": f"IP found on interface {interface.name} on router {router.name}",
                        "references": [],
                    }

        return None

    def _resolve_from_neighbor_map(self, ip):

        entry = self.neighbor_map.get(ip)

        if not entry:
            return None

        return {
            "resolved": True,
            "ip": ip,
            "confidence": entry.get("confidence", "medium"),
            "method": "neighbor_map",
            "router": entry.get("router"),
            "vrf": entry.get("vrf"),
            "interface": entry.get("interface"),
            "reason": entry.get(
                "reason",
                f"IP resolved from static neighbor map to {entry.get('router')}"
            ),
            "references": [],
        }

    def _resolve_from_asa_interface(self, ip):

        for node in self.graph.nodes.values():

            if node.type != "ASAInterface":
                continue

            if node.properties.get("ip") != ip:
                continue

            context = node.properties.get("context")
            nameif = node.properties.get("interface")
            subnet = node.properties.get("subnet")

            firewall = None

            context_node = self.graph.find("Context", context)

            if context_node:
                for relation, neighbor in self.graph.neighbors(context_node.id):
                    if relation == "HAS_CONTEXT" and neighbor.type == "Firewall":
                        firewall = neighbor.name
                        break

            return {
                "resolved": True,
                "ip": ip,
                "confidence": "high",
                "method": "asa_interface",
                "firewall": firewall,
                "context": context,
                "interface": nameif,
                "subnet": subnet,
                "reason": f"IP found on ASA interface {context}:{nameif}",
                "references": [],
            }

        return None

    def _find_route_references(self, ip):
        references = []

        for route in self.routes:
            if route.get("next_hop") == ip:
                references.append(
                    {
                        "router": route.get("router"),
                        "vrf": route.get("vrf"),
                        "prefix": route.get("prefix"),
                        "protocol": route.get("protocol"),
                    }
                )

        return references