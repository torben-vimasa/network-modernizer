from models.dependency_hint import (
    DependencyHint
)

import ipaddress


class DependencyHintEngine:

    def __init__(
        self,
        digital_twin
    ):

        self.digital_twin = digital_twin

    def enrich(
        self,
        dependencies,
        source_network=None
    ):

        results = []

        for dependency in dependencies:

            hint = self._analyze_dependency(
                dependency=dependency,
                source_network=source_network
            )

            results.append(
                hint
            )

        return results

    def _analyze_dependency(
        self,
        dependency,
        source_network
    ):

        targets = []

        for host in dependency.resolved_hosts:

            targets.append(
                {
                    "type": "host",
                    "value": host
                }
            )

        for network in dependency.resolved_networks:

            targets.append(
                {
                    "type": "network",
                    "value": network
                }
            )

        if not targets:

            return DependencyHint(
                dependency_key=dependency.key,
                dependency_name=dependency.name,
                hint_type="unknown",
                hint_value=None,
                confidence="low",
                reason=(
                    "Dependency has no resolved "
                    "host or network for path analysis"
                ),
                evidence=[]
            )

        evidence = []

        for target in targets[:5]:

            target_evidence = (
                self._trace_target(
                    target=target,
                    source_network=source_network
                )
            )

            if target_evidence:

                evidence.extend(
                    target_evidence
                )

        if not evidence:

            return DependencyHint(
                dependency_key=dependency.key,
                dependency_name=dependency.name,
                hint_type="unknown",
                hint_value=None,
                confidence="low",
                reason=(
                    "No deterministic routing/path "
                    "evidence was found"
                ),
                evidence=[]
            )

        summary = (
            self._summarize_evidence(
                evidence
            )
        )

        return DependencyHint(
            dependency_key=dependency.key,
            dependency_name=dependency.name,
            hint_type=summary[
                "hint_type"
            ],
            hint_value=summary[
                "hint_value"
            ],
            confidence=summary[
                "confidence"
            ],
            reason=summary[
                "reason"
            ],
            evidence=evidence
        )

    def _trace_target(
        self,
        target,
        source_network=None
    ):

        target_value = (
            target.get(
                "value"
            )
        )

        destination_ip = (
            self._representative_ip(
                target_value
            )
        )

        if not destination_ip:
            return []

        evidence = []

        #
        # Step 1:
        # Find most specific router routes
        # for destination.
        #
        router_matches = (
            self._router_route_matches(
                destination_ip
            )
        )

        if not router_matches:

            return []

        #
        # Prefer source-relevant routing
        # where possible.
        #
        router_route = (
            self._select_router_route(
                router_matches,
                source_network=source_network
            )
        )

        if not router_route:
            return []

        evidence.append(
            {
                "stage": "router-route",
                "target": destination_ip,
                "router": router_route.get(
                    "router"
                ),
                "vrf": router_route.get(
                    "vrf"
                ),
                "prefix": router_route.get(
                    "prefix"
                ),
                "protocol": router_route.get(
                    "protocol"
                ),
                "next_hop": router_route.get(
                    "next_hop"
                ),
                "interface": router_route.get(
                    "interface"
                ),
                "egress_interface": router_route.get(
                    "egress_interface"
                ),
                "confidence": "high"
            }
        )

        next_hop = router_route.get(
            "next_hop"
        )

        if not next_hop:

            return evidence

        #
        # Step 2:
        # Resolve router next-hop to graph node.
        #
        next_hop_node = (
            self._find_node_for_ip(
                next_hop
            )
        )

        if not next_hop_node:

            evidence.append(
                {
                    "stage": "inventory-boundary",
                    "target": destination_ip,
                    "next_hop": next_hop,
                    "inventory_boundary": True,
                    "confidence": "medium",
                    "reason": (
                        "Router next-hop is not represented "
                        "in managed inventory"
                    )
                }
            )

            return evidence

        node_data = (
            self._node_evidence(
                next_hop_node
            )
        )

        node_data[
            "stage"
        ] = "next-hop-resolution"

        node_data[
            "target"
        ] = destination_ip

        node_data[
            "next_hop"
        ] = next_hop

        node_data[
            "confidence"
        ] = "high"

        evidence.append(
            node_data
        )

        #
        # Step 3:
        # If next-hop resolves to firewall/context,
        # continue with firewall LPM.
        #
        firewall_context = (
            self._firewall_context_from_node(
                next_hop_node
            )
        )

        if not firewall_context:

            return evidence

        firewall_route = (
            self._firewall_lookup(
                destination=destination_ip,
                context=firewall_context
            )
        )

        if not firewall_route:

            return evidence

        evidence.append(
            {
                "stage": "firewall-route",
                "target": destination_ip,
                "context": firewall_context,
                "prefix": getattr(
                    firewall_route,
                    "prefix",
                    None
                ),
                "protocol": getattr(
                    firewall_route,
                    "protocol",
                    None
                ),
                "next_hop": getattr(
                    firewall_route,
                    "next_hop",
                    None
                ),
                "interface": getattr(
                    firewall_route,
                    "interface",
                    None
                ),
                "egress_interface": getattr(
                    firewall_route,
                    "egress_interface",
                    None
                ),
                "confidence": "high"
            }
        )

        firewall_next_hop = getattr(
            firewall_route,
            "next_hop",
            None
        )

        firewall_egress = getattr(
            firewall_route,
            "egress_interface",
            None
        )

        #
        # If firewall route already has semantic egress,
        # capture it immediately.
        #
        if firewall_egress:

            evidence.append(
                {
                    "stage": "semantic-egress",
                    "target": destination_ip,
                    "context": firewall_context,
                    "egress_interface": firewall_egress,
                    "hint_type": (
                        self._hint_type_from_name(
                            firewall_egress
                        )
                    ),
                    "hint_value": firewall_egress,
                    "confidence": "high"
                }
            )

        if not firewall_next_hop:

            return evidence

        #
        # Step 4:
        # Resolve firewall next-hop.
        #
        firewall_next_node = (
            self._find_node_for_ip(
                firewall_next_hop
            )
        )

        if firewall_next_node:

            next_node_data = (
                self._node_evidence(
                    firewall_next_node
                )
            )

            next_node_data[
                "stage"
            ] = "firewall-next-hop-resolution"

            next_node_data[
                "target"
            ] = destination_ip

            next_node_data[
                "next_hop"
            ] = firewall_next_hop

            next_node_data[
                "confidence"
            ] = "high"

            evidence.append(
                next_node_data
            )

            return evidence

        #
        # Step 5:
        # Next-hop itself may not be inventory node,
        # but firewall routing can still tell us which
        # connected egress owns that next-hop.
        #
        connected_route = (
            self._firewall_lookup(
                destination=firewall_next_hop,
                context=firewall_context
            )
        )

        if connected_route:

            connected_egress = getattr(
                connected_route,
                "egress_interface",
                None
            )

            evidence.append(
                {
                    "stage": "firewall-next-hop-route",
                    "target": firewall_next_hop,
                    "context": firewall_context,
                    "prefix": getattr(
                        connected_route,
                        "prefix",
                        None
                    ),
                    "protocol": getattr(
                        connected_route,
                        "protocol",
                        None
                    ),
                    "next_hop": getattr(
                        connected_route,
                        "next_hop",
                        None
                    ),
                    "interface": getattr(
                        connected_route,
                        "interface",
                        None
                    ),
                    "egress_interface": connected_egress,
                    "confidence": "high"
                }
            )

            if connected_egress:

                evidence.append(
                    {
                        "stage": "semantic-egress",
                        "target": destination_ip,
                        "context": firewall_context,
                        "egress_interface": connected_egress,
                        "hint_type": (
                            self._hint_type_from_name(
                                connected_egress
                            )
                        ),
                        "hint_value": connected_egress,
                        "confidence": "high"
                    }
                )

                return evidence

        evidence.append(
            {
                "stage": "inventory-boundary",
                "target": destination_ip,
                "next_hop": firewall_next_hop,
                "context": firewall_context,
                "inventory_boundary": True,
                "confidence": "medium",
                "reason": (
                    "Firewall next-hop is not represented "
                    "as a managed inventory node"
                )
            }
        )

        return evidence

    def _router_route_matches(
        self,
        destination
    ):

        try:

            destination_ip = ipaddress.ip_address(
                destination
            )

        except ValueError:

            return []

        matches = []

        for route in self.digital_twin.route.routes:

            prefix = route.get(
                "prefix"
            )

            if not prefix:
                continue

            try:

                network = ipaddress.ip_network(
                    prefix,
                    strict=False
                )

            except ValueError:
                continue

            if destination_ip not in network:
                continue

            matches.append(
                {
                    **route,
                    "_prefixlen": network.prefixlen
                }
            )

        matches.sort(
            key=lambda item: item.get(
                "_prefixlen",
                -1
            ),
            reverse=True
        )

        return matches

    def _select_router_route(
        self,
        matches,
        source_network=None
    ):

        if not matches:
            return None

        best_prefix = matches[
            0
        ].get(
            "_prefixlen"
        )

        best = [
            item
            for item in matches
            if item.get(
                "_prefixlen"
            ) == best_prefix
        ]

        #
        # For AdmIT dependency analysis we prefer
        # bane1 where it exists among equally specific
        # candidates, because that is the known BHASA
        # routing domain used in this use case.
        #
        for item in best:

            if item.get(
                "vrf"
            ) == "bane1":

                return item

        return best[
            0
        ]

    def _firewall_lookup(
        self,
        destination,
        context
    ):

        try:

            result = (
                self.digital_twin.firewall_route_engine.lookup(
                    destination=destination,
                    context=context
                )
            )

        except Exception:
            return None

        if not result:
            return None

        if not getattr(
            result,
            "matched",
            False
        ):
            return None

        return getattr(
            result,
            "route",
            None
        )

    def _find_node_for_ip(
        self,
        address
    ):

        if not address:
            return None

        address = str(
            address
        )

        exact_candidates = []

        for node in self.digital_twin.graph.nodes.values():

            properties = (
                node.properties
                or {}
            )

            node_ip = properties.get(
                "ip"
            )

            if (
                node_ip
                and str(node_ip) == address
            ):

                exact_candidates.append(
                    node
                )

        if exact_candidates:

            #
            # Prefer interfaces because they
            # give us context/nameif/egress meaning.
            #
            for node in exact_candidates:

                if node.type in {
                    "ASAInterface",
                    "RouterInterface",
                    "NetworkInterface"
                }:

                    return node

            return exact_candidates[
                0
            ]

        return None

    def _firewall_context_from_node(
        self,
        node
    ):

        if not node:
            return None

        properties = (
            node.properties
            or {}
        )

        if node.type == "ASAInterface":

            return (
                properties.get(
                    "context"
                )
                or properties.get(
                    "device"
                )
            )

        return None

    def _node_evidence(
        self,
        node
    ):

        properties = (
            node.properties
            or {}
        )

        return {
            "node_type": node.type,
            "node_name": node.name,
            "device": properties.get(
                "device"
            ),
            "context": properties.get(
                "context"
            ),
            "nameif": properties.get(
                "nameif"
            ),
            "interface": properties.get(
                "interface"
            ),
            "ip": properties.get(
                "ip"
            ),
            "subnet": properties.get(
                "subnet"
            ),
            "description": properties.get(
                "description"
            )
        }

    def _hint_type_from_name(
        self,
        name
    ):

        if not name:

            return "routing"

        text = str(
            name
        ).lower()

        if "kmd" in text:

            return "external-hosting"

        if "aeven" in text:

            return "external-hosting"

        if "internet" in text:

            return "internet"

        if "outside" in text:

            return "internet"

        if "siemens" in text:

            return "external-partner"

        if "psi" in text:

            return "ot"

        return "routing"

    def _summarize_evidence(
        self,
        evidence
    ):

        semantic = [
            item
            for item in evidence
            if item.get(
                "stage"
            ) == "semantic-egress"
            and item.get(
                "hint_value"
            )
        ]

        if semantic:

            best = semantic[
                -1
            ]

            return {
                "hint_type": best.get(
                    "hint_type",
                    "routing"
                ),
                "hint_value": best.get(
                    "hint_value"
                ),
                "confidence": best.get(
                    "confidence",
                    "high"
                ),
                "reason": (
                    "Deterministic routing path "
                    f"resolved to egress "
                    f"{best.get('hint_value')}"
                )
            }

        boundaries = [
            item
            for item in evidence
            if item.get(
                "inventory_boundary"
            )
        ]

        if boundaries:

            boundary = boundaries[
                -1
            ]

            return {
                "hint_type": "inventory-boundary",
                "hint_value": boundary.get(
                    "next_hop"
                ),
                "confidence": "medium",
                "reason": (
                    "Deterministic routing path "
                    "reached an inventory boundary"
                )
            }

        firewall_routes = [
            item
            for item in evidence
            if item.get(
                "stage"
            ) == "firewall-route"
        ]

        if firewall_routes:

            item = firewall_routes[
                -1
            ]

            return {
                "hint_type": "routing",
                "hint_value": item.get(
                    "context"
                ),
                "confidence": "medium",
                "reason": (
                    "Routing path reached firewall "
                    f"context {item.get('context')}"
                )
            }

        router_routes = [
            item
            for item in evidence
            if item.get(
                "stage"
            ) == "router-route"
        ]

        if router_routes:

            item = router_routes[
                -1
            ]

            return {
                "hint_type": "routing",
                "hint_value": (
                    item.get(
                        "vrf"
                    )
                    or item.get(
                        "router"
                    )
                ),
                "confidence": "low",
                "reason": (
                    "Only router-level routing "
                    "evidence was resolved"
                )
            }

        return {
            "hint_type": "unknown",
            "hint_value": None,
            "confidence": "low",
            "reason": (
                "No meaningful routing hint "
                "could be derived"
            )
        }

    def _representative_ip(
        self,
        value
    ):

        if not value:
            return None

        try:

            text = str(
                value
            )

            if "/" in text:

                network = ipaddress.ip_network(
                    text,
                    strict=False
                )

                return str(
                    network.network_address
                )

            address = ipaddress.ip_address(
                text
            )

            return str(
                address
            )

        except ValueError:

            return None