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
            router=summary.get(
                "router"
            ),
            vrf=summary.get(
                "vrf"
            ),
            interface=summary.get(
                "interface"
            ),
            subnet=summary.get(
                "subnet"
            ),
            evidence=evidence
        )

    def _trace_target(
        self,
        target,
        source_network
    ):

        evidence = []

        destination_ip = (
            self._representative_ip(
                target.get(
                    "value"
                )
            )
        )

        if not destination_ip:
            return evidence

        #
        # Step 1:
        # Find best initial router route.
        #
        router_matches = (
            self._router_route_matches(
                destination_ip
            )
        )

        router_route = (
            self._select_router_route(
                matches=router_matches,
                source_network=source_network
            )
        )

        if not router_route:
            return evidence

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
        # Resolve initial router next-hop.
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
        # Step 3A:
        # Router -> firewall continuation.
        #
        firewall_context = (
            self._firewall_context_from_node(
                next_hop_node
            )
        )

        if firewall_context:

            evidence.extend(
                self._trace_firewall_context(
                    destination_ip=destination_ip,
                    firewall_context=firewall_context,
                    visited_contexts=set(),
                    depth=0,
                    max_depth=8
                )
            )

            return evidence

        #
        # Step 3B:
        # Router -> router continuation.
        #
        if next_hop_node.type == "RouterInterface":

            next_router = (
                next_hop_node.properties.get(
                    "router"
                )
                or next_hop_node.properties.get(
                    "device"
                )
            )

            if not next_router:

                node_name = getattr(
                    next_hop_node,
                    "name",
                    ""
                )

                if ":" in node_name:

                    next_router = (
                        node_name.split(
                            ":",
                            1
                        )[0]
                    )

            if next_router:

                evidence.extend(
                    self._trace_router_context(
                        destination_ip=destination_ip,
                        router_name=next_router,
                        vrf=router_route.get(
                            "vrf"
                        ),
                        visited_routers={
                            (
                                router_route.get(
                                    "router"
                                ),
                                router_route.get(
                                    "vrf"
                                )
                            )
                        },
                        depth=1,
                        max_depth=8
                    )
                )

        return evidence

    def _trace_router_context(
        self,
        destination_ip,
        router_name,
        vrf,
        visited_routers=None,
        depth=0,
        max_depth=8
    ):

        evidence = []

        if visited_routers is None:
            visited_routers = set()

        if depth > max_depth:
            return evidence

        visit_key = (
            router_name,
            vrf
        )

        if visit_key in visited_routers:
            return evidence

        visited_routers = set(
            visited_routers
        )

        visited_routers.add(
            visit_key
        )

        #
        # Same VRF first.
        #
        route = self.digital_twin.route.lookup(
            router_name,
            vrf,
            destination_ip
        )

        used_vrf = vrf

        #
        # Fall back to global/all only when
        # the same VRF has no route.
        #
        if not route and vrf != "all":

            route = self.digital_twin.route.lookup(
                router_name,
                "all",
                destination_ip
            )

            used_vrf = "all"

        if not route:
            return evidence

        evidence.append(
            {
                "stage": "router-route",
                "target": destination_ip,
                "router": router_name,
                "vrf": used_vrf,
                "prefix": route.get(
                    "prefix"
                ),
                "protocol": route.get(
                    "protocol"
                ),
                "next_hop": route.get(
                    "next_hop"
                ),
                "interface": route.get(
                    "exit_interface"
                ),
                "egress_interface": None,
                "confidence": "high"
            }
        )

        next_hop = route.get(
            "next_hop"
        )

        exit_interface = route.get(
            "exit_interface"
        )

        #
        # Connected/local route: we have reached
        # a deterministic router egress.
        #
        if not next_hop:

            if exit_interface:

                evidence.append(
                    {
                        "stage": "router-egress",
                        "target": destination_ip,
                        "router": router_name,
                        "vrf": used_vrf,
                        "egress_interface": exit_interface,
                        "confidence": "high"
                    }
                )

            return evidence

        next_node = self._find_node_for_ip(
            next_hop
        )

        if not next_node:

            evidence.append(
                {
                    "stage": "inventory-boundary",
                    "target": destination_ip,
                    "router": router_name,
                    "vrf": used_vrf,
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

        node_data = self._node_evidence(
            next_node
        )

        node_data["stage"] = (
            "router-next-hop-resolution"
        )
        node_data["target"] = destination_ip
        node_data["next_hop"] = next_hop
        node_data["confidence"] = "high"

        evidence.append(
            node_data
        )

        #
        # Router -> firewall.
        #
        firewall_context = (
            self._firewall_context_from_node(
                next_node
            )
        )

        if firewall_context:

            evidence.extend(
                self._trace_firewall_context(
                    destination_ip=destination_ip,
                    firewall_context=firewall_context,
                    visited_contexts=set(),
                    depth=0,
                    max_depth=8
                )
            )

            return evidence

        #
        # Router -> router.
        #
        if next_node.type == "RouterInterface":

            next_router = (
                next_node.properties.get(
                    "router"
                )
                or next_node.properties.get(
                    "device"
                )
            )

            if not next_router:

                node_name = getattr(
                    next_node,
                    "name",
                    ""
                )

                if ":" in node_name:
                    next_router = node_name.split(
                        ":",
                        1
                    )[0]

            if next_router:

                evidence.extend(
                    self._trace_router_context(
                        destination_ip=destination_ip,
                        router_name=next_router,
                        vrf=used_vrf,
                        visited_routers=visited_routers,
                        depth=depth + 1,
                        max_depth=max_depth
                    )
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


    def _find_hsrp_nodes_for_ip(
        self,
        address
    ):

        if not address:
            return []

        address = str(
            address
        )

        candidates = []

        for node in self.digital_twin.graph.nodes.values():

            if node.type != "RouterInterface":
                continue

            properties = (
                node.properties
                or {}
            )

            virtual_ip = properties.get(
                "hsrp_virtual_ip"
            )

            if (
                virtual_ip
                and str(virtual_ip) == address
            ):

                candidates.append(
                    node
                )

        return candidates

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

        #
        # Extract strongest deterministic
        # forwarding facts first.
        #
        terminal_router_route = None

        for item in reversed(
            evidence
        ):

            if item.get(
                "stage"
            ) != "router-route":
                continue

            if item.get(
                "protocol"
            ) not in (
                "connected",
                "local"
            ):
                continue

            terminal_router_route = item
            break

        forwarding = {
            "router": None,
            "vrf": None,
            "interface": None,
            "subnet": None
        }

        if terminal_router_route:

            forwarding[
                "router"
            ] = terminal_router_route.get(
                "router"
            )

            forwarding[
                "vrf"
            ] = terminal_router_route.get(
                "vrf"
            )

            forwarding[
                "interface"
            ] = (
                terminal_router_route.get(
                    "interface"
                )
                or terminal_router_route.get(
                    "egress_interface"
                )
            )

            forwarding[
                "subnet"
            ] = terminal_router_route.get(
                "prefix"
            )

        #
        # 1. Semantic egress evidence is strongest.
        #
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

            semantic_by_value = {}

            for item in semantic:

                value = item.get(
                    "hint_value"
                )

                if value not in semantic_by_value:

                    semantic_by_value[
                        value
                    ] = item

            semantic_values = list(
                semantic_by_value.keys()
            )

            if len(
                semantic_values
            ) == 1:

                best = semantic_by_value[
                    semantic_values[0]
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
                    ),
                    **forwarding
                }

            semantic_types = sorted(
                {
                    item.get(
                        "hint_type",
                        "routing"
                    )
                    for item
                    in semantic_by_value.values()
                }
            )

            return {
                "hint_type": "mixed",
                "hint_value": None,
                "confidence": "high",
                "reason": (
                    "Dependency members resolve through "
                    "multiple semantic egresses: "
                    + ", ".join(
                        semantic_values
                    )
                    + " ("
                    + ", ".join(
                        semantic_types
                    )
                    + ")"
                ),
                **forwarding
            }

        #
        # 2. Connected router egress.
        #
        router_egresses = [
            item
            for item in evidence
            if item.get(
                "stage"
            ) == "router-egress"
            and item.get(
                "egress_interface"
            )
        ]

        if router_egresses:

            egress_values = []

            for item in router_egresses:

                value = item.get(
                    "egress_interface"
                )

                if (
                    value
                    and value not in egress_values
                ):

                    egress_values.append(
                        value
                    )

            if len(
                egress_values
            ) == 1:

                return {
                    "hint_type": "routing",
                    "hint_value": forwarding.get(
                        "vrf"
                    ),
                    "confidence": "high",
                    "reason": (
                        "Deterministic router path "
                        "resolved to connected network "
                        f"{forwarding.get('subnet')} "
                        f"via {forwarding.get('interface')}"
                    ),
                    **forwarding
                }

            return {
                "hint_type": "mixed",
                "hint_value": None,
                "confidence": "high",
                "reason": (
                    "Dependency members resolve through "
                    "multiple connected router egresses: "
                    + ", ".join(
                        egress_values
                    )
                ),
                **forwarding
            }

        #
        # 3. Inventory boundary.
        #
        boundaries = [
            item
            for item in evidence
            if item.get(
                "inventory_boundary"
            )
        ]

        if boundaries:

            boundary_values = []

            for item in boundaries:

                value = item.get(
                    "next_hop"
                )

                if (
                    value
                    and value not in boundary_values
                ):

                    boundary_values.append(
                        value
                    )

            if len(
                boundary_values
            ) > 1:

                return {
                    "hint_type": "mixed",
                    "hint_value": None,
                    "confidence": "medium",
                    "reason": (
                        "Dependency members reached "
                        "multiple inventory boundaries: "
                        + ", ".join(
                            boundary_values
                        )
                    ),
                    **forwarding
                }

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
                ),
                **forwarding
            }

        #
        # 4. Firewall context.
        #
        firewall_routes = [
            item
            for item in evidence
            if item.get(
                "stage"
            ) == "firewall-route"
        ]

        if firewall_routes:

            contexts = []

            for item in firewall_routes:

                context = item.get(
                    "context"
                )

                if (
                    context
                    and context not in contexts
                ):

                    contexts.append(
                        context
                    )

            if len(
                contexts
            ) > 1:

                return {
                    "hint_type": "mixed",
                    "hint_value": None,
                    "confidence": "medium",
                    "reason": (
                        "Dependency members traverse "
                        "multiple firewall contexts: "
                        + ", ".join(
                            contexts
                        )
                    ),
                    **forwarding
                }

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
                ),
                **forwarding
            }

        #
        # 5. Router-level evidence only.
        #
        router_routes = [
            item
            for item in evidence
            if item.get(
                "stage"
            ) == "router-route"
        ]

        if router_routes:

            routing_domains = []

            for item in router_routes:

                value = (
                    item.get(
                        "vrf"
                    )
                    or item.get(
                        "router"
                    )
                )

                if (
                    value
                    and value not in routing_domains
                ):

                    routing_domains.append(
                        value
                    )

            if len(
                routing_domains
            ) > 1:

                return {
                    "hint_type": "mixed",
                    "hint_value": None,
                    "confidence": "low",
                    "reason": (
                        "Dependency members resolve "
                        "through multiple routing domains: "
                        + ", ".join(
                            routing_domains
                        )
                    ),
                    **forwarding
                }

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
                ),
                **forwarding
            }

        return {
            "hint_type": "unknown",
            "hint_value": None,
            "confidence": "low",
            "reason": (
                "No meaningful routing hint "
                "could be derived"
            ),
            **forwarding
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

    def _trace_firewall_context(
        self,
        destination_ip,
        firewall_context,
        visited_contexts=None,
        depth=0,
        max_depth=8
    ):

        evidence = []

        if visited_contexts is None:
            visited_contexts = set()

        if depth > max_depth:

            evidence.append(
                {
                    "stage": "inventory-boundary",
                    "target": destination_ip,
                    "context": firewall_context,
                    "inventory_boundary": True,
                    "confidence": "low",
                    "reason": (
                        "Maximum firewall traversal "
                        "depth reached"
                    )
                }
            )

            return evidence

        if firewall_context in visited_contexts:

            evidence.append(
                {
                    "stage": "inventory-boundary",
                    "target": destination_ip,
                    "context": firewall_context,
                    "inventory_boundary": True,
                    "confidence": "medium",
                    "reason": (
                        "Firewall traversal loop detected"
                    )
                }
            )

            return evidence

        visited_contexts = set(
            visited_contexts
        )

        visited_contexts.add(
            firewall_context
        )

        #
        # Step 1:
        # Route lookup inside current firewall context.
        #
        firewall_route = self._firewall_lookup(
            destination=destination_ip,
            context=firewall_context
        )

        if not firewall_route:
            return evidence

        firewall_egress = getattr(
            firewall_route,
            "egress_interface",
            None
        )

        firewall_next_hop = getattr(
            firewall_route,
            "next_hop",
            None
        )

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
                "next_hop": firewall_next_hop,
                "interface": getattr(
                    firewall_route,
                    "interface",
                    None
                ),
                "egress_interface": firewall_egress,
                "confidence": "high"
            }
        )

        #
        # A route with an egress interface is terminal only
        # when it has no next-hop.
        #
        # If a next-hop exists, the interface merely describes
        # how that next-hop is reached and path tracing must
        # continue through the managed topology.
        #
        if firewall_egress and not firewall_next_hop:

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

            return evidence

        if not firewall_next_hop:
            return evidence

        #
        # Step 3:
        # Resolve next-hop as an exact inventory IP.
        #
        firewall_next_node = self._find_node_for_ip(
            firewall_next_hop
        )

        if firewall_next_node:

            next_node_data = self._node_evidence(
                firewall_next_node
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

            #
            # Firewall -> firewall continuation.
            #
            next_context = (
                self._firewall_context_from_node(
                    firewall_next_node
                )
            )

            if next_context:

                evidence.extend(
                    self._trace_firewall_context(
                        destination_ip=destination_ip,
                        firewall_context=next_context,
                        visited_contexts=visited_contexts,
                        depth=depth + 1,
                        max_depth=max_depth
                    )
                )

                return evidence

            #
            # Firewall -> router continuation.
            #
            if firewall_next_node.type == "RouterInterface":

                next_router = (
                    firewall_next_node.properties.get(
                        "router"
                    )
                    or firewall_next_node.properties.get(
                        "device"
                    )
                )

                next_vrf = (
                    firewall_next_node.properties.get(
                        "vrf"
                    )
                )

                if next_router and next_vrf:

                    evidence.extend(
                        self._trace_router_context(
                            destination_ip=destination_ip,
                            router_name=next_router,
                            vrf=next_vrf,
                            visited_routers=set(),
                            depth=depth + 1,
                            max_depth=max_depth
                        )
                    )

                    return evidence

        #
        # Step 4:
        # Resolve next-hop as an HSRP virtual IP.
        #
        # An HSRP VIP can legitimately belong to
        # multiple RouterInterface nodes. Do not
        # guess which router is currently active.
        #
        hsrp_nodes = self._find_hsrp_nodes_for_ip(
            firewall_next_hop
        )

        if hsrp_nodes:

            hsrp_vrfs = {
                node.properties.get(
                    "vrf"
                )
                for node in hsrp_nodes
                if node.properties.get(
                    "vrf"
                )
            }

            hsrp_routers = {
                (
                    node.properties.get(
                        "router"
                    )
                    or node.properties.get(
                        "device"
                    )
                )
                for node in hsrp_nodes
                if (
                    node.properties.get(
                        "router"
                    )
                    or node.properties.get(
                        "device"
                    )
                )
            }

            hsrp_interfaces = {
                (
                    node.properties.get(
                        "interface"
                    )
                    or getattr(
                        node,
                        "name",
                        None
                    )
                )
                for node in hsrp_nodes
                if (
                    node.properties.get(
                        "interface"
                    )
                    or getattr(
                        node,
                        "name",
                        None
                    )
                )
            }

            evidence.append(
                {
                    "stage": "hsrp-next-hop-resolution",
                    "target": destination_ip,
                    "next_hop": firewall_next_hop,
                    "routers": sorted(
                        hsrp_routers
                    ),
                    "vrfs": sorted(
                        hsrp_vrfs
                    ),
                    "interfaces": sorted(
                        hsrp_interfaces
                    ),
                    "confidence": "high"
                }
            )

            #
            # All HSRP owners must agree on VRF
            # before deterministic continuation.
            #
            if (
                len(hsrp_vrfs) == 1
                and hsrp_routers
            ):

                hsrp_vrf = next(
                    iter(
                        hsrp_vrfs
                    )
                )

                branch_found = False

                for hsrp_router in sorted(
                    hsrp_routers
                ):

                    branch_evidence = (
                        self._trace_router_context(
                            destination_ip=destination_ip,
                            router_name=hsrp_router,
                            vrf=hsrp_vrf,
                            visited_routers=set(),
                            depth=depth + 1,
                            max_depth=max_depth
                        )
                    )

                    if branch_evidence:

                        branch_found = True

                        evidence.extend(
                            branch_evidence
                        )

                if branch_found:
                    return evidence

        #
        # Step 5:
        # The next-hop may not itself exist as an
        # inventory node, but the firewall routing
        # table may identify the connected egress
        # network that owns it.
        #
        connected_route = self._firewall_lookup(
            destination=firewall_next_hop,
            context=firewall_context
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

        #
        # Step 6:
        # We have exhausted deterministic inventory
        # resolution for this firewall next-hop.
        #
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