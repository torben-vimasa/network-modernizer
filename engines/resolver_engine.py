import ipaddress
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

        with open(routes_file, "r", encoding="utf-8") as f:
            self.routes = json.load(f)

    # ------------------------------------------------------------------
    # Resolve a next-hop IP
    # ------------------------------------------------------------------

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
                "reason": (
                    f"IP is used as next-hop by "
                    f"{len(references)} route entries"
                ),
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

    # ------------------------------------------------------------------
    # Resolve a packet source
    # ------------------------------------------------------------------

    def resolve_source(self, source_ip):

        result = self.resolve_ip(source_ip)

        if result.get("resolved"):
            return result

        router_matches = self._resolve_source_router(source_ip)
        firewall_matches = self._resolve_source_firewalls(source_ip)

        all_matches = router_matches + firewall_matches

        if len(all_matches) == 1:
            return all_matches[0]

        if len(all_matches) > 1:
            return {
                "resolved": False,
                "method": "source_subnet_ambiguous",
                "reason": (
                    f"Source {source_ip} matched "
                    f"{len(all_matches)} interfaces"
                ),
                "candidates": all_matches,
                "confidence": "low"
            }

        return {
            "resolved": False,
            "method": "source_unresolved",
            "reason": f"Could not resolve source {source_ip}",
            "confidence": "low",
            "candidates": []
        }

    # ------------------------------------------------------------------
    # Router source lookup
    # ------------------------------------------------------------------

    def _resolve_source_router(self, source_ip):

        matches = []
        address = ipaddress.ip_address(source_ip)

        for node in self.graph.nodes.values():

            if node.type not in ["RouterInterface", "Interface"]:
                continue

            ip = node.properties.get("ip")
            mask = node.properties.get("mask")

            if not ip or not mask:
                continue

            try:
                network = ipaddress.ip_network(
                    f"{ip}/{mask}",
                    strict=False
                )
            except ValueError:
                continue

            if address not in network:
                continue

            router = self._find_parent_device(
                node,
                allowed_types={"Router"}
            )

            if not router:
                continue

            vrf = self._find_interface_vrf(node)

            matches.append(
                {
                    "resolved": True,
                    "method": "source_router_subnet",
                    "router": router.name,
                    "device": router.name,
                    "device_type": "Router",
                    "interface": node.name,
                    "vrf": vrf,
                    "reason": (
                        f"Source {source_ip} is in subnet "
                        f"{network} on {node.name}"
                    ),
                    "confidence": "medium"
                }
            )

        return matches

    # ------------------------------------------------------------------
    # Firewall source lookup
    # ------------------------------------------------------------------

    def _resolve_source_firewalls(self, source_ip):

        matches = []
        address = ipaddress.ip_address(source_ip)

        for node in self.graph.nodes.values():

            if node.type != "ASAInterface":
                continue

            ip = node.properties.get("ip")
            mask = node.properties.get("mask")

            if not ip or not mask:
                continue

            try:
                network = ipaddress.ip_network(
                    f"{ip}/{mask}",
                    strict=False
                )
            except ValueError:
                continue

            if address not in network:
                continue

            context = (
                node.properties.get("context")
                or node.properties.get("device")
            )

            firewall = self._find_parent_device(
                node,
                allowed_types={"Firewall", "Context"}
            )

            firewall_name = (
                firewall.name
                if firewall
                else context
            )

            interface_name = (
                node.properties.get("nameif")
                or node.properties.get("interface")
                or node.name
            )

            matches.append(
                {
                    "resolved": True,
                    "method": "source_firewall_subnet",
                    "device": firewall_name,
                    "device_type": "Firewall",
                    "firewall": firewall_name,
                    "context": context,
                    "interface": interface_name,
                    "vrf": context,
                    "reason": (
                        f"Source {source_ip} is in subnet "
                        f"{network} on ASA interface {node.name}"
                    ),
                    "confidence": "medium"
                }
            )

        return matches

    # ------------------------------------------------------------------
    # Existing next-hop resolution methods
    # ------------------------------------------------------------------

    def _resolve_from_router_inventory(self, ip):

        ip_node = self.graph.find("IPAddress", ip)

        if ip_node:

            for relation, interface in self.graph.neighbors(ip_node.id):

                if relation != "HAS_IP":
                    continue

                if interface.type not in [
                    "Interface",
                    "RouterInterface"
                ]:
                    continue

                router = self._find_parent_device(
                    interface,
                    allowed_types={"Router"}
                )

                if not router:
                    continue

                return {
                    "resolved": True,
                    "ip": ip,
                    "confidence": "high",
                    "method": "router_inventory",
                    "router": router.name,
                    "vrf": self._find_interface_vrf(interface),
                    "interface": (
                        interface.properties.get("name")
                        or interface.name
                    ),
                    "subnet": interface.properties.get("subnet"),
                    "reason": (
                        f"IP found on interface "
                        f"{interface.name} on router {router.name}"
                    ),
                    "references": [],
                }

        for node in self.graph.nodes.values():

            if node.type not in [
                "Interface",
                "RouterInterface"
            ]:
                continue

            node_ip = node.properties.get("ip")

            if not node_ip:
                continue

            if str(node_ip).split("/")[0] != ip:
                continue

            router = self._find_parent_device(
                node,
                allowed_types={"Router"}
            )

            if not router:
                continue

            return {
                "resolved": True,
                "ip": ip,
                "confidence": "high",
                "method": "router_inventory",
                "router": router.name,
                "vrf": self._find_interface_vrf(node),
                "interface": node.name,
                "subnet": node.properties.get("subnet"),
                "reason": (
                    f"IP found on interface "
                    f"{node.name} on router {router.name}"
                ),
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
            "confidence": entry.get(
                "confidence",
                "medium"
            ),
            "method": "neighbor_map",
            "router": entry.get("router"),
            "vrf": entry.get("vrf"),
            "interface": entry.get("interface"),
            "reason": entry.get(
                "reason",
                (
                    f"IP resolved from static neighbor map "
                    f"to {entry.get('router')}"
                )
            ),
            "references": [],
        }

    def _resolve_from_asa_interface(self, ip):

        for node in self.graph.nodes.values():

            if node.type != "ASAInterface":
                continue

            node_ip = node.properties.get("ip")

            if not node_ip:
                continue

            if str(node_ip).split("/")[0] != ip:
                continue

            context = (
                node.properties.get("context")
                or node.properties.get("device")
            )

            nameif = (
                node.properties.get("nameif")
                or node.properties.get("interface")
                or node.name
            )

            subnet = node.properties.get("subnet")

            firewall = self._find_parent_device(
                node,
                allowed_types={"Firewall", "Context"}
            )

            firewall_name = (
                firewall.name
                if firewall
                else context
            )

            return {
                "resolved": True,
                "ip": ip,
                "confidence": "high",
                "method": "asa_interface",
                "firewall": firewall_name,
                "context": context,
                "interface": nameif,
                "subnet": subnet,
                "reason": (
                    f"IP found on ASA interface "
                    f"{context}:{nameif}"
                ),
                "references": [],
            }

        return None

    def _find_route_references(self, ip):

        references = []

        for route in self.routes:

            if route.get("next_hop") != ip:
                continue

            references.append(
                {
                    "router": route.get("router"),
                    "vrf": route.get("vrf"),
                    "prefix": route.get("prefix"),
                    "protocol": route.get("protocol"),
                }
            )

        return references

    # ------------------------------------------------------------------
    # Graph helpers
    # ------------------------------------------------------------------

    def _find_parent_device(
        self,
        interface_node,
        allowed_types
    ):

        for relation, neighbor in self.graph.neighbors(
            interface_node.id
        ):

            if relation != "HAS_INTERFACE":
                continue

            if neighbor.type in allowed_types:
                return neighbor

        return None

    def _find_interface_vrf(self, interface_node):

        vrf = interface_node.properties.get("vrf")

        if vrf:
            return vrf

        for relation, neighbor in self.graph.neighbors(
            interface_node.id
        ):

            if (
                relation == "BELONGS_TO_VRF"
                and neighbor.type == "VRF"
            ):
                return neighbor.name

        return None