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
    # Resolve an explicit or automatic trace start
    # ------------------------------------------------------------------

    def resolve_start(self, start=None, source_ip=None):

        if not start:
            if not source_ip:
                return {
                    "resolved": False,
                    "method": "source_unresolved",
                    "reason": "No source IP supplied for automatic resolution",
                    "confidence": "low",
                    "candidates": []
                }

            return self.resolve_source(source_ip)

        if not isinstance(start, dict):
            return {
                "resolved": False,
                "method": "invalid_explicit_start",
                "reason": "Explicit start must be a JSON object",
                "confidence": "low",
                "candidates": []
            }

        start_type = str(start.get("type") or "").strip().lower()

        if start_type == "router":
            router = start.get("router") or start.get("device")
            vrf = start.get("vrf")
            interface = start.get("interface")

            if not router or not vrf:
                return {
                    "resolved": False,
                    "method": "invalid_explicit_router_start",
                    "reason": "Explicit router start requires router and vrf",
                    "confidence": "low",
                    "candidates": []
                }

            if not self.graph.find("Router", router):
                return {
                    "resolved": False,
                    "method": "explicit_router_not_found",
                    "reason": f"Router {router} was not found in the graph",
                    "confidence": "low",
                    "candidates": []
                }

            return {
                "resolved": True,
                "method": "explicit_router_start",
                "device_type": "Router",
                "device": router,
                "router": router,
                "firewall": None,
                "context": None,
                "vrf": vrf,
                "interface": interface,
                "ip": source_ip,
                "subnet": None,
                "reason": (
                    f"Trace start explicitly set to "
                    f"router {router} VRF {vrf}"
                ),
                "confidence": "high",
                "references": [],
                "candidates": []
            }

        if start_type == "firewall":
            context = start.get("context")
            interface = (
                start.get("interface")
                or start.get("ingress_interface")
            )

            if not context or not interface:
                return {
                    "resolved": False,
                    "method": "invalid_explicit_firewall_start",
                    "reason": (
                        "Explicit firewall start requires "
                        "context and interface"
                    ),
                    "confidence": "low",
                    "candidates": []
                }

            return self._resolve_explicit_firewall_start(
                context=context,
                interface=interface,
                source_ip=source_ip
            )

        return {
            "resolved": False,
            "method": "unsupported_explicit_start",
            "reason": f"Unsupported explicit start type {start.get('type')!r}",
            "confidence": "low",
            "candidates": []
        }

    def _resolve_explicit_firewall_start(
        self,
        context,
        interface,
        source_ip=None
    ):

        context_key = str(context).lower()
        interface_key = str(interface).lower()
        matches = []

        for node in self.graph.nodes.values():

            if node.type != "ASAInterface":
                continue

            node_context = (
                node.properties.get("context")
                or node.properties.get("device")
            )

            node_interface = (
                node.properties.get("nameif")
                or node.properties.get("interface")
                or node.name
            )

            node_suffix = node.name.split(":", 1)[-1]

            context_matches = (
                str(node_context).lower() == context_key
                or node.name.lower().startswith(f"{context_key}:")
            )

            interface_matches = (
                str(node_interface).lower() == interface_key
                or node_suffix.lower() == interface_key
            )

            if context_matches and interface_matches:
                matches.append(node)

        if not matches:
            return {
                "resolved": False,
                "method": "explicit_firewall_interface_not_found",
                "reason": (
                    f"ASA interface {context}:{interface} "
                    f"was not found in the graph"
                ),
                "confidence": "low",
                "candidates": []
            }

        node = sorted(matches, key=lambda item: item.name)[0]

        firewall = self._find_parent_device(
            node,
            allowed_types={"Firewall", "Context"}
        )

        firewall_name = (
            firewall.name
            if firewall
            else node.properties.get("device") or context
        )

        interface_name = (
            node.properties.get("nameif")
            or node.properties.get("interface")
            or interface
        )

        resolved_context = (
            node.properties.get("context")
            or node.properties.get("device")
            or context
        )

        return {
            "resolved": True,
            "method": "asa_interface",
            "device_type": "Firewall",
            "device": firewall_name,
            "router": None,
            "firewall": firewall_name,
            "context": resolved_context,
            "vrf": None,
            "interface": interface_name,
            "ip": source_ip,
            "subnet": node.properties.get("subnet"),
            "reason": (
                f"Trace start explicitly set to ASA interface "
                f"{resolved_context}:{interface_name}"
            ),
            "confidence": "high",
            "references": [],
            "candidates": [item.name for item in matches]
        }

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

            router_matches = [
                match
                for match in all_matches
                if match.get("device_type") == "Router"
            ]

            firewall_matches = [
                match
                for match in all_matches
                if match.get("device_type") == "Firewall"
            ]

            if router_matches and not firewall_matches:

                vrfs = {
                    match.get("vrf")
                    for match in router_matches
                }

                if len(vrfs) == 1:

                    ranked = []

                    for match in router_matches:

                        interface_name = match.get(
                            "interface"
                        )

                        node = None

                        if interface_name:
                            node = self.graph.nodes.get(
                                f"RouterInterface:{interface_name}"
                            )

                        properties = (
                            node.properties
                            if node
                            else {}
                        )

                        hsrp_state = (
                            properties.get(
                                "hsrp_state"
                            )
                        )

                        hsrp_priority = (
                            properties.get(
                                "hsrp_priority"
                            )
                        )

                        hsrp_virtual_ip = (
                            properties.get(
                                "hsrp_virtual_ip"
                            )
                        )

                        #
                        # Ranking:
                        #
                        # 1. Explicit HSRP Active state
                        # 2. Highest HSRP priority
                        # 3. Candidate participating in HSRP
                        # 4. Deterministic router-name fallback
                        #
                        active_rank = (
                            1
                            if str(hsrp_state).lower() == "active"
                            else 0
                        )

                        priority_rank = (
                            hsrp_priority
                            if hsrp_priority is not None
                            else -1
                        )

                        hsrp_rank = (
                            1
                            if hsrp_virtual_ip
                            else 0
                        )

                        ranked.append(
                            (
                                active_rank,
                                priority_rank,
                                hsrp_rank,
                                match
                            )
                        )

                    ranked.sort(
                        key=lambda item: (
                            -item[0],
                            -item[1],
                            -item[2],
                            item[3].get("router") or ""
                        )
                    )

                    selected = dict(
                        ranked[0][3]
                    )

                    selected["method"] = (
                        "source_router_redundant"
                    )

                    selected["confidence"] = (
                        "high"
                        if ranked[0][0] == 1
                        else "medium"
                    )

                    selected["candidates"] = (
                        router_matches
                    )

                    selected["reason"] = (
                        f"Source {source_ip} matched "
                        f"{len(router_matches)} redundant router interfaces; "
                        f"selected {selected.get('router')} "
                        f"using gateway redundancy evidence"
                    )

                    return selected

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