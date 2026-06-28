import json
from pathlib import Path


class ResolverEngine:

    def __init__(self, graph, routes_file=Path("output/routes.json")):
        self.graph = graph

        with open(routes_file, "r") as f:
            self.routes = json.load(f)

    def resolve_ip(self, ip):
        direct = self._resolve_from_graph(ip)

        if direct:
            return direct

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

    def _resolve_from_graph(self, ip):
        ip_node = self.graph.find("IPAddress", ip)

        if not ip_node:
            return None

        for relation, interface in self.graph.neighbors(ip_node.id):
            if relation != "HAS_IP":
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
                        "interface": interface.name,
                        "reason": f"IP found on interface {interface.name} on router {router.name}",
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