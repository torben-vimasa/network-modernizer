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

        #
        # Explicit ASA address ranges do not naturally appear in
        # resolved_hosts/resolved_networks.  Expand them into the
        # smallest exact set of forwarding targets so the existing
        # tracing logic can analyse the complete range without
        # choosing an arbitrary representative host.
        #
        endpoint_types = set(
            getattr(
                dependency,
                "endpoint_types",
                []
            )
        )

        if (
            not targets
            and endpoint_types == {"range"}
            and str(dependency.key).startswith("range:")
        ):
            range_value = str(dependency.key)[
                len("range:"):
            ]

            try:
                start_text, end_text = (
                    range_value.split("-", 1)
                )

                start_ip = ipaddress.ip_address(
                    start_text
                )
                end_ip = ipaddress.ip_address(
                    end_text
                )

                range_networks = list(
                    ipaddress.summarize_address_range(
                        start_ip,
                        end_ip
                    )
                )

            except (
                ValueError,
                TypeError
            ):
                range_networks = []

            for network in range_networks:

                if network.prefixlen == network.max_prefixlen:
                    targets.append(
                        {
                            "type": "host",
                            "value": str(
                                network.network_address
                            )
                        }
                    )

                else:
                    targets.append(
                        {
                            "type": "network",
                            "value": str(network)
                        }
                    )

        target_count = len(targets)

        if not targets:

            endpoint_types = set(
                getattr(
                    dependency,
                    "endpoint_types",
                    []
                )
            )

            unresolved = list(
                getattr(
                    dependency,
                    "unresolved",
                    []
                )
            )

            def _looks_like_fqdn(value):

                text = str(value).strip()

                if not text or "." not in text:
                    return False

                try:
                    ipaddress.ip_address(text)
                    return False

                except ValueError:
                    pass

                labels = text.rstrip(".").split(".")

                if len(labels) < 2:
                    return False

                return all(
                    label
                    and len(label) <= 63
                    and not label.startswith("-")
                    and not label.endswith("-")
                    and all(
                        ch.isalnum() or ch == "-"
                        for ch in label
                    )
                    for label in labels
                )

            unresolved_fqdn = (
                "fqdn" in endpoint_types
                or (
                    unresolved
                    and all(
                        _looks_like_fqdn(value)
                        for value in unresolved
                    )
                )
            )

            if unresolved_fqdn:

                return DependencyHint(
                    dependency_key=dependency.key,
                    dependency_name=dependency.name,
                    hint_type="unresolved-fqdn",
                    hint_value=dependency.name,
                    confidence="low",
                    reason=(
                        "Configured FQDN dependency; "
                        "no resolved host or network "
                        "evidence is available for "
                        "path analysis"
                    ),
                    evidence=[],
                    target_count=0,
                    attempted_target_count=0,
                    evidence_target_count=0,
                    coverage="not-applicable"
                )

            if endpoint_types == {"any"}:

                return DependencyHint(
                    dependency_key=dependency.key,
                    dependency_name=dependency.name,
                    hint_type="wildcard",
                    hint_value=dependency.name,
                    confidence="low",
                    reason=(
                        "Configured wildcard dependency; "
                        "no single host or network can "
                        "be used for path analysis"
                    ),
                    evidence=[],
                    target_count=0,
                    attempted_target_count=0,
                    evidence_target_count=0,
                    coverage="not-applicable"
                )

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
                evidence=[],
                target_count=0,
                attempted_target_count=0,
                evidence_target_count=0,
                coverage="not-applicable"
            )

        directions = list(
            getattr(
                dependency,
                "directions",
                []
            )
            or []
        )

        #
        # Direction is forwarding truth, not presentation
        # metadata.  A path cannot be selected safely when
        # the dependency direction is unknown or conflicting.
        #
        if len(directions) != 1:

            evidence = [
                {
                    "stage": "source-resolution",
                    "source_resolution": "ambiguous",
                    "directions": directions,
                    "confidence": "low",
                    "reason": (
                        "Dependency does not have one "
                        "unambiguous forwarding direction"
                    )
                }
            ]

            return DependencyHint(
                dependency_key=dependency.key,
                dependency_name=dependency.name,
                hint_type="source-unresolved",
                hint_value=None,
                confidence="low",
                reason=(
                    "Forwarding source cannot be selected "
                    "because dependency direction is "
                    "missing or ambiguous"
                ),
                evidence=evidence,
                target_count=target_count,
                attempted_target_count=0,
                evidence_target_count=0,
                coverage="not-applicable"
            )

        direction = directions[0]

        if direction not in {
            "outbound",
            "inbound"
        }:

            evidence = [
                {
                    "stage": "source-resolution",
                    "source_resolution": "unsupported-direction",
                    "direction": direction,
                    "confidence": "low",
                    "reason": (
                        "Dependency direction is not "
                        "supported for deterministic "
                        "forwarding analysis"
                    )
                }
            ]

            return DependencyHint(
                dependency_key=dependency.key,
                dependency_name=dependency.name,
                hint_type="source-unresolved",
                hint_value=None,
                confidence="low",
                reason=(
                    "Forwarding source cannot be selected "
                    f"for direction {direction}"
                ),
                evidence=evidence,
                target_count=target_count,
                attempted_target_count=0,
                evidence_target_count=0,
                coverage="not-applicable"
            )

        attempted_targets = targets[:5]

        attempted_target_count = len(
            attempted_targets
        )

        evidence = []

        evidence_target_count = 0

        for target in attempted_targets:

            target_evidence = (
                self._trace_target(
                    target=target,
                    source_network=source_network,
                    direction=direction
                )
            )

            if target_evidence:

                evidence_target_count += 1

                #
                # Preserve the original dependency member.
                #
                for item in target_evidence:

                    item["analysis_target"] = (
                        target.get("value")
                    )

                    item["analysis_target_type"] = (
                        target.get("type")
                    )

                    item["analysis_direction"] = (
                        direction
                    )

                evidence.extend(
                    target_evidence
                )

        if target_count > attempted_target_count:

            coverage = "sampled"

        else:

            coverage = "full"

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
                evidence=[],
                target_count=target_count,
                attempted_target_count=attempted_target_count,
                evidence_target_count=evidence_target_count,
                coverage=coverage
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
            evidence=evidence,
            target_count=target_count,
            attempted_target_count=attempted_target_count,
            evidence_target_count=evidence_target_count,
            coverage=coverage
        )

    def _trace_target(
        self,
        target,
        source_network,
        direction
    ):

        #
        # Direction determines which endpoint is the
        # forwarding source.
        #
        # outbound:
        #   query/source_network -> dependency target
        #
        # inbound:
        #   dependency target -> query/source_network
        #
        if direction == "outbound":

            traversal_source = source_network
            traversal_destination = target.get(
                "value"
            )

        elif direction == "inbound":

            traversal_source = target.get(
                "value"
            )
            traversal_destination = source_network

        else:

            return []

        if not traversal_source:

            return [
                {
                    "stage": "source-resolution",
                    "source_resolution": "unresolved",
                    "direction": direction,
                    "confidence": "low",
                    "reason": (
                        "No forwarding source was supplied "
                        "for dependency path analysis"
                    )
                }
            ]

        #
        # Resolve the actual source side.
        #
        source_anchors = (
            self._resolve_source_anchors(
                traversal_source
            )
        )

        if not source_anchors:

            return [
                {
                    "stage": "source-resolution",
                    "source": traversal_source,
                    "destination": traversal_destination,
                    "source_resolution": "unresolved",
                    "direction": direction,
                    "confidence": "low",
                    "reason": (
                        "No deterministic source attachment "
                        "could be established from direct "
                        "normalized topology ownership or "
                        "complete explicit source-prefix "
                        "routing to a connected boundary"
                    )
                }
            ]

        #
        # Multiple direct source routing domains are a real
        # ambiguity.  Do not choose one by ordering, name,
        # VRF preference, device preference or use case.
        #
        unique_scopes = {
            (
                item.get("type"),
                item.get("device"),
                item.get("scope")
            )
            for item in source_anchors
        }

        if len(unique_scopes) != 1:

            return [
                {
                    "stage": "source-resolution",
                    "source": traversal_source,
                    "destination": traversal_destination,
                    "source_resolution": "ambiguous",
                    "direction": direction,
                    "candidates": source_anchors,
                    "confidence": "low",
                    "reason": (
                        "Multiple source routing contexts "
                        "are supported by normalized "
                        "evidence; no context was selected "
                        "implicitly"
                    )
                }
            ]

        source_anchor = source_anchors[0]

        source_resolution_method = (
            source_anchor.get(
                "resolution_method"
            )
            or "direct"
        )

        if (
            source_resolution_method
            == "routing-boundary"
        ):

            source_reason = (
                "Forwarding source resolved from "
                "complete explicit source-prefix routing "
                "coverage to a directly connected "
                "next-hop boundary"
            )

        else:

            source_reason = (
                "Forwarding source resolved from "
                "direct normalized topology ownership"
            )

        evidence = [
            {
                "stage": "source-resolution",
                "source": traversal_source,
                "destination": traversal_destination,
                "source_resolution": (
                    source_resolution_method
                ),
                "direction": direction,
                "device_type": source_anchor.get(
                    "type"
                ),
                "device": source_anchor.get(
                    "device"
                ),
                "scope": source_anchor.get(
                    "scope"
                ),
                "interface": source_anchor.get(
                    "interface"
                ),
                "ip": source_anchor.get(
                    "ip"
                ),
                "next_hop": source_anchor.get(
                    "next_hop"
                ),
                "route_prefixes": source_anchor.get(
                    "route_prefixes"
                ),
                "confidence": "high",
                "reason": source_reason
            }
        ]

        #
        # A CIDR destination may contain multiple forwarding
        # partitions.  Selecting an arbitrary host from the
        # network would silently claim path equivalence.
        #
        destination_ip = (
            self._representative_ip(
                traversal_destination
            )
        )

        if not destination_ip:

            evidence.append(
                {
                    "stage": "destination-resolution",
                    "destination": traversal_destination,
                    "confidence": "low",
                    "reason": (
                        "Destination could not be normalized "
                        "to an IP forwarding target"
                    )
                }
            )

            return evidence

        source_type = source_anchor.get(
            "type"
        )

        if source_type == "RouterInterface":

            router_name = source_anchor.get(
                "device"
            )

            vrf = source_anchor.get(
                "scope"
            )

            if not router_name or not vrf:

                evidence.append(
                    {
                        "stage": "source-resolution",
                        "source": traversal_source,
                        "source_resolution": "incomplete",
                        "confidence": "low",
                        "reason": (
                            "Direct router source attachment "
                            "does not contain both router "
                            "and routing scope"
                        )
                    }
                )

                return evidence

            evidence.extend(
                self._trace_router_context(
                    destination_ip=destination_ip,
                    router_name=router_name,
                    vrf=vrf,
                    visited_routers=set(),
                    visited_contexts=set(),
                    depth=0,
                    max_depth=8
                )
            )

            return evidence

        if source_type == "ASAInterface":

            firewall_context = source_anchor.get(
                "scope"
            )

            if not firewall_context:

                evidence.append(
                    {
                        "stage": "source-resolution",
                        "source": traversal_source,
                        "source_resolution": "incomplete",
                        "confidence": "low",
                        "reason": (
                            "Direct firewall source attachment "
                            "does not contain a firewall context"
                        )
                    }
                )

                return evidence

            evidence.extend(
                self._trace_firewall_context(
                    destination_ip=destination_ip,
                    firewall_context=firewall_context,
                    visited_routers=set(),
                    visited_contexts=set(),
                    depth=0,
                    max_depth=8
                )
            )

            return evidence

        evidence.append(
            {
                "stage": "source-resolution",
                "source": traversal_source,
                "source_resolution": "unsupported",
                "device_type": source_type,
                "confidence": "low",
                "reason": (
                    "Direct source ownership exists but "
                    "its infrastructure type is not yet "
                    "supported for deterministic traversal"
                )
            }
        )

        return evidence

    def _resolve_source_anchors(
        self,
        source
    ):

        if not source:
            return []

        resolver = (
            self.digital_twin
            .flow_trace_engine
            .endpoint_resolver
        )

        text = str(
            source
        )

        requested_network = None
        requested_host = None

        #
        # Network source:
        #
        # Direct normalized subnet ownership remains the
        # strongest source evidence.
        #
        if "/" in text:

            try:

                requested_network = (
                    ipaddress.ip_network(
                        text,
                        strict=False
                    )
                )

            except ValueError:

                return []

            resolution = (
                resolver.resolve_network(
                    str(requested_network)
                )
            )

            infrastructure = []

            if resolution.get(
                "found"
            ):

                resolved_subnet = resolution.get(
                    "subnet"
                )

                if resolved_subnet:

                    try:

                        normalized_subnet = (
                            ipaddress.ip_network(
                                str(resolved_subnet),
                                strict=False
                            )
                        )

                    except ValueError:

                        normalized_subnet = None

                    if (
                        normalized_subnet
                        == requested_network
                    ):

                        infrastructure = (
                            resolution.get(
                                "infrastructure",
                                []
                            )
                        )

        #
        # Host source:
        #
        # Only direct subnet ownership is accepted here.
        # A route_match is not direct ownership.
        #
        else:

            try:

                requested_host = (
                    ipaddress.ip_address(
                        text
                    )
                )

            except ValueError:

                return []

            resolution = (
                resolver.resolve(
                    text
                )
            )

            infrastructure = []

            if (
                resolution.get(
                    "found"
                )
                and resolution.get(
                    "method"
                ) in {
                    "direct",
                    "direct_subnet",
                    "subnet"
                }
            ):

                infrastructure = (
                    resolution.get(
                        "infrastructure",
                        []
                    )
                )

        anchors = []

        for item in infrastructure:

            if item.get(
                "role"
            ) != "direct":

                continue

            item_type = item.get(
                "type"
            )

            device = (
                (
                    item.get(
                        "devices"
                    )
                    or [None]
                )[0]
            )

            if item_type == "RouterInterface":

                scopes = (
                    item.get(
                        "vrfs"
                    )
                    or []
                )

            elif item_type == "ASAInterface":

                scopes = (
                    item.get(
                        "contexts"
                    )
                    or []
                )

            else:

                continue

            for scope in scopes:

                if not device or not scope:
                    continue

                anchor = {
                    "type": item_type,
                    "device": device,
                    "scope": scope,
                    "interface": item.get(
                        "interface"
                    ),
                    "ip": item.get(
                        "ip"
                    ),
                    "resolution_method": "direct"
                }

                if anchor not in anchors:

                    anchors.append(
                        anchor
                    )

        #
        # Direct ownership always wins.
        #
        if anchors:
            return anchors

        #
        # Routing-derived source boundaries use different
        # evidence rules for networks and individual hosts.
        #
        # Network:
        #   The complete requested prefix must be explicitly
        #   covered by exact and/or more-specific routes.
        #
        # Host:
        #   Use longest-prefix-match inside each independent
        #   routing scope.  A host route is not required; an
        #   explicit covering route is valid forwarding
        #   evidence for the individual address.
        #
        # In both cases the selected route must lead to a
        # next-hop that is directly connected in the same
        # device/routing scope.
        #
        if requested_network is not None:

            return self._resolve_routing_source_anchors(
                requested_network
            )

        if requested_host is not None:

            return (
                self._resolve_routing_host_source_anchors(
                    requested_host
                )
            )

        return []


    def _resolve_routing_host_source_anchors(
        self,
        requested_host
    ):

        #
        # Resolve an individual source host from explicit
        # firewall routing evidence.
        #
        # Longest-prefix-match is evaluated independently
        # inside each routing table.  Routes from unrelated
        # devices/contexts must never compete in one global
        # LPM decision.
        #
        routes_by_scope = {}

        firewall_routes = getattr(
            self.digital_twin.firewall_route_engine,
            "routes",
            []
        )

        for route in firewall_routes:

            prefix = getattr(
                route,
                "prefix",
                None
            )

            if not prefix:
                continue

            try:

                network = ipaddress.ip_network(
                    str(prefix),
                    strict=False
                )

            except ValueError:

                continue

            if requested_host not in network:
                continue

            #
            # A default route is valid forwarding behaviour,
            # but by itself is not sufficiently specific
            # evidence to establish a source-side boundary.
            #
            if network.prefixlen == 0:
                continue

            router = getattr(
                route,
                "router",
                None
            )

            vrf = getattr(
                route,
                "vrf",
                None
            )

            if not router or not vrf:
                continue

            scope_key = (
                str(router),
                str(vrf)
            )

            routes_by_scope.setdefault(
                scope_key,
                []
            ).append(
                {
                    "route": route,
                    "network": network
                }
            )

        candidates = []

        for (
            router,
            vrf
        ), entries in routes_by_scope.items():

            #
            # Ordinary LPM, but only within this routing
            # table.
            #
            longest_prefix = max(
                item["network"].prefixlen
                for item in entries
            )

            best_entries = [
                item
                for item in entries
                if item["network"].prefixlen
                == longest_prefix
            ]

            #
            # Group duplicate observations by next-hop.
            #
            by_next_hop = {}

            for item in best_entries:

                route = item["route"]

                next_hop = getattr(
                    route,
                    "next_hop",
                    None
                )

                if not next_hop:
                    continue

                by_next_hop.setdefault(
                    str(next_hop),
                    []
                ).append(
                    item
                )

            for (
                next_hop,
                next_hop_entries
            ) in by_next_hop.items():

                explicit_egress = {
                    getattr(
                        item["route"],
                        "egress_interface",
                        None
                    )
                    or getattr(
                        item["route"],
                        "interface",
                        None
                    )
                    or getattr(
                        item["route"],
                        "exit_interface",
                        None
                    )
                    for item in next_hop_entries
                }

                explicit_egress.discard(
                    None
                )

                #
                # Conflicting explicit egress interfaces are
                # genuine ambiguity.  Do not select one.
                #
                if len(explicit_egress) > 1:
                    continue

                expected_interface = (
                    next(
                        iter(
                            explicit_egress
                        )
                    )
                    if explicit_egress
                    else None
                )

                #
                # The next-hop must be directly connected in
                # the same device/routing scope that supplied
                # the route evidence.
                #
                interface_nodes = (
                    self._find_interfaces_for_connected_ip(
                        next_hop,
                        device=router,
                        scope=vrf
                    )
                )

                #
                # A directly-connected next-hop is not necessarily
                # the source-side routing boundary.
                #
                # Before treating the current egress interface as a
                # boundary, ask the normalized Knowledge Graph whether
                # the next-hop has an exact identity as an internal
                # router function.
                #
                # Router interface addresses and FHRP virtual addresses
                # are positive routing-continuation evidence.  Merely
                # sharing a subnet is not sufficient, and firewall
                # interface addresses are deliberately not treated as
                # continuation evidence here.
                #
                known_managed_next_hop = (
                    self._find_node_for_ip(
                        next_hop
                    )
                )

                known_hsrp_next_hops = (
                    self._find_hsrp_nodes_for_ip(
                        next_hop
                    )
                )

                if (
                    known_managed_next_hop
                    or known_hsrp_next_hops
                ):
                    continue

                for node in interface_nodes:

                    properties = (
                        node.properties
                        or {}
                    )

                    interface_name = (
                        properties.get(
                            "nameif"
                        )
                        or properties.get(
                            "interface"
                        )
                    )

                    if (
                        expected_interface
                        and interface_name
                        != expected_interface
                    ):
                        continue

                    if node.type == "ASAInterface":

                        scope = (
                            properties.get(
                                "context"
                            )
                            or properties.get(
                                "device"
                            )
                        )

                        device = (
                            properties.get(
                                "device"
                            )
                            or router
                        )

                    elif node.type == "RouterInterface":

                        scope = (
                            properties.get(
                                "vrf"
                            )
                            or vrf
                        )

                        device = (
                            properties.get(
                                "router"
                            )
                            or properties.get(
                                "device"
                            )
                            or router
                        )

                    else:
                        continue

                    if not device or not scope:
                        continue

                    candidate = {
                        "type": node.type,
                        "device": device,
                        "scope": scope,
                        "interface": interface_name,
                        "ip": properties.get(
                            "ip"
                        ),
                        "resolution_method": (
                            "routing-boundary"
                        ),
                        "source_host": str(
                            requested_host
                        ),
                        "next_hop": next_hop,
                        "route_prefixes": sorted(
                            {
                                str(
                                    item["network"]
                                )
                                for item
                                in next_hop_entries
                            }
                        )
                    }

                    if candidate not in candidates:

                        candidates.append(
                            candidate
                        )

        #
        # LPM has already been evaluated independently inside
        # each routing table above.
        #
        # Do not compare prefix lengths across unrelated routing
        # domains.  A more-specific route in one context proves
        # forwarding knowledge in that context; it does not prove
        # that the context is physically or logically closer to
        # the endpoint.
        #
        # Preserve every independently supported topology-boundary
        # candidate.  The caller will report multiple routing
        # contexts as ambiguous rather than selecting one.
        #
        return candidates


    def _resolve_routing_source_anchors(
        self,
        requested_network
    ):

        #
        # Collect explicit firewall routes related to the
        # requested source network.
        #
        # RouteEntry uses router + vrf as routing scope.
        #
        routes_by_scope = {}

        firewall_routes = getattr(
            self.digital_twin.firewall_route_engine,
            "routes",
            []
        )

        for route in firewall_routes:

            prefix = getattr(
                route,
                "prefix",
                None
            )

            if not prefix:
                continue

            try:

                network = ipaddress.ip_network(
                    str(prefix),
                    strict=False
                )

            except ValueError:

                continue

            #
            # Only exact and more-specific prefixes are
            # explicit evidence for coverage of the source
            # network.
            #
            if not (
                network == requested_network
                or network.subnet_of(
                    requested_network
                )
            ):
                continue

            router = getattr(
                route,
                "router",
                None
            )

            vrf = getattr(
                route,
                "vrf",
                None
            )

            if not router or not vrf:
                continue

            scope_key = (
                str(router),
                str(vrf)
            )

            routes_by_scope.setdefault(
                scope_key,
                []
            ).append(
                {
                    "route": route,
                    "network": network
                }
            )

        candidates = []

        for (
            router,
            vrf
        ), entries in routes_by_scope.items():

            #
            # First prove that the union of explicit routes
            # covers the complete requested source network.
            #
            networks = [
                item["network"]
                for item in entries
            ]

            if not self._network_fully_covered(
                requested_network,
                networks
            ):
                continue

            #
            # Group observations by next-hop.
            #
            # Duplicate observations with and without an
            # egress interface do not create separate paths
            # when they agree on routing scope and next-hop.
            #
            by_next_hop = {}

            for item in entries:

                route = item["route"]

                next_hop = getattr(
                    route,
                    "next_hop",
                    None
                )

                if not next_hop:
                    continue

                by_next_hop.setdefault(
                    str(next_hop),
                    []
                ).append(
                    item
                )

            for (
                next_hop,
                next_hop_entries
            ) in by_next_hop.items():

                #
                # The routes using this next-hop must
                # themselves cover the complete source
                # network.  Otherwise this is only a partial
                # source boundary.
                #
                if not self._network_fully_covered(
                    requested_network,
                    [
                        item["network"]
                        for item in next_hop_entries
                    ]
                ):
                    continue

                explicit_egress = {
                    getattr(
                        item["route"],
                        "egress_interface",
                        None
                    )
                    or getattr(
                        item["route"],
                        "interface",
                        None
                    )
                    or getattr(
                        item["route"],
                        "exit_interface",
                        None
                    )
                    for item in next_hop_entries
                }

                explicit_egress.discard(
                    None
                )

                #
                # Conflicting explicit egress interfaces are
                # real ambiguity.
                #
                if len(
                    explicit_egress
                ) > 1:
                    continue

                expected_interface = (
                    next(
                        iter(
                            explicit_egress
                        )
                    )
                    if explicit_egress
                    else None
                )

                interface_nodes = (
                    self._find_interfaces_for_connected_ip(
                        next_hop,
                        device=router,
                        scope=vrf
                    )
                )

                #
                # A directly-connected next-hop is not necessarily
                # the source-side routing boundary.
                #
                # If the normalized Knowledge Graph identifies the
                # next-hop exactly as an internal router interface
                # or HSRP virtual address, forwarding continues
                # inside managed topology and the current egress
                # interface must not be classified as a boundary.
                #
                known_managed_next_hop = (
                    self._find_node_for_ip(
                        next_hop
                    )
                )

                known_hsrp_next_hops = (
                    self._find_hsrp_nodes_for_ip(
                        next_hop
                    )
                )

                if (
                    known_managed_next_hop
                    or known_hsrp_next_hops
                ):
                    continue
                for node in interface_nodes:

                    properties = (
                        node.properties
                        or {}
                    )

                    interface_name = (
                        properties.get(
                            "nameif"
                        )
                        or properties.get(
                            "interface"
                        )
                    )

                    if (
                        expected_interface
                        and interface_name
                        != expected_interface
                    ):
                        continue

                    if node.type == "ASAInterface":

                        scope = (
                            properties.get(
                                "context"
                            )
                            or properties.get(
                                "device"
                            )
                        )

                        device = (
                            properties.get(
                                "device"
                            )
                            or router
                        )

                    elif node.type == "RouterInterface":

                        scope = (
                            properties.get(
                                "vrf"
                            )
                            or vrf
                        )

                        device = (
                            properties.get(
                                "router"
                            )
                            or properties.get(
                                "device"
                            )
                            or router
                        )

                    else:
                        continue

                    if not device or not scope:
                        continue

                    candidate = {
                        "type": node.type,
                        "device": device,
                        "scope": scope,
                        "interface": interface_name,
                        "ip": properties.get(
                            "ip"
                        ),
                        "resolution_method": (
                            "routing-boundary"
                        ),
                        "source_network": str(
                            requested_network
                        ),
                        "next_hop": next_hop,
                        "route_prefixes": sorted(
                            {
                                str(
                                    item["network"]
                                )
                                for item
                                in next_hop_entries
                            }
                        )
                    }

                    if candidate not in candidates:

                        candidates.append(
                            candidate
                        )

        return candidates


    def _network_fully_covered(
        self,
        requested_network,
        networks
    ):

        valid = []

        for network in networks:

            try:

                candidate = (
                    network
                    if isinstance(
                        network,
                        (
                            ipaddress.IPv4Network,
                            ipaddress.IPv6Network
                        )
                    )
                    else ipaddress.ip_network(
                        str(network),
                        strict=False
                    )
                )

            except ValueError:

                continue

            if (
                candidate == requested_network
                or candidate.subnet_of(
                    requested_network
                )
            ):

                valid.append(
                    candidate
                )

        if not valid:
            return False

        collapsed = list(
            ipaddress.collapse_addresses(
                valid
            )
        )

        remaining = [
            requested_network
        ]

        for covering in collapsed:

            new_remaining = []

            for part in remaining:

                if covering == part:
                    continue

                if covering.supernet_of(
                    part
                ):
                    continue

                if covering.subnet_of(
                    part
                ):

                    new_remaining.extend(
                        part.address_exclude(
                            covering
                        )
                    )

                    continue

                new_remaining.append(
                    part
                )

            remaining = new_remaining

            if not remaining:
                return True

        return False


    def _is_known_router_next_hop(
        self,
        address
    ):
        """
        Return True only when the normalized Knowledge Graph
        identifies the address exactly as an internal router
        forwarding identity.

        Exact RouterInterface addresses and FHRP virtual IPs are
        routing-continuation evidence.

        Same-subnet membership is intentionally insufficient.
        ASA/firewall interface identity is intentionally not used
        here as router-continuation evidence.
        """

        try:

            target_ip = ipaddress.ip_address(
                str(address)
            )

        except ValueError:

            return False

        for node in (
            self.digital_twin
            .graph
            .nodes
            .values()
        ):

            if node.type != "RouterInterface":
                continue

            properties = (
                node.properties
                or {}
            )

            for key in (
                "ip",
                "hsrp_virtual_ip"
            ):

                value = properties.get(
                    key
                )

                if not value:
                    continue

                try:

                    candidate_ip = (
                        ipaddress.ip_address(
                            str(value)
                        )
                    )

                except ValueError:

                    continue

                if candidate_ip == target_ip:
                    return True

        return False
    def _find_interfaces_for_connected_ip(
        self,
        address,
        device=None,
        scope=None
    ):

        try:

            target_ip = ipaddress.ip_address(
                str(address)
            )

        except ValueError:

            return []

        matches = []

        for node in (
            self.digital_twin
            .graph
            .nodes
            .values()
        ):

            if node.type not in {
                "ASAInterface",
                "RouterInterface"
            }:
                continue

            properties = (
                node.properties
                or {}
            )

            node_device = (
                properties.get(
                    "device"
                )
                or properties.get(
                    "router"
                )
            )

            node_scope = (
                properties.get(
                    "context"
                )
                if node.type
                == "ASAInterface"
                else properties.get(
                    "vrf"
                )
            )

            #
            # Keep source-boundary resolution inside the
            # routing table that supplied the route evidence.
            #
            if (
                device
                and node_device
                and str(node_device)
                != str(device)
            ):
                continue

            if (
                scope
                and node_scope
                and str(node_scope)
                != str(scope)
            ):
                continue

            node_ip = properties.get(
                "ip"
            )

            if not node_ip:
                continue

            subnet = None

            mask = properties.get(
                "mask"
            )

            prefix = properties.get(
                "prefix"
            )

            try:

                if mask:

                    subnet = (
                        ipaddress.ip_network(
                            f"{node_ip}/{mask}",
                            strict=False
                        )
                    )

                elif prefix:

                    subnet = (
                        ipaddress.ip_network(
                            str(prefix),
                            strict=False
                        )
                    )

            except ValueError:

                subnet = None

            if not subnet:
                continue

            if target_ip not in subnet:
                continue

            matches.append(
                node
            )

        return matches


    def _trace_router_context(
        self,
        destination_ip,
        router_name,
        vrf,
        visited_routers=None,
        visited_contexts=None,
        depth=0,
        max_depth=8
    ):

        evidence = []

        if visited_routers is None:
            visited_routers = set()

        if visited_contexts is None:
            visited_contexts = set()

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
        # Connected/direct/local routes are terminal
        # router forwarding facts. Different route
        # sources normalize them differently:
        #
        # - connected commonly exposes exit_interface
        # - direct commonly exposes the local interface
        #   address as next_hop
        # - local may use either representation
        #
        # Resolve a local next-hop only to recover the
        # interface identity. Do not recurse through the
        # router's own interface as another forwarding hop.
        #
        route_protocol = str(
            route.get(
                "protocol"
            )
            or ""
        ).lower()

        if route_protocol in (
            "connected",
            "direct",
            "local"
        ):

            terminal_interface = exit_interface

            if (
                not terminal_interface
                and next_hop
            ):

                local_node = self._find_node_for_ip(
                    next_hop
                )

                if (
                    local_node
                    and local_node.type
                    == "RouterInterface"
                ):

                    local_data = self._node_evidence(
                        local_node
                    )

                    local_device = (
                        local_data.get(
                            "device"
                        )
                        or ""
                    )

                    if (
                        local_device
                        == router_name
                    ):

                        terminal_interface = (
                            local_data.get(
                                "interface"
                            )
                        )

            evidence.append(
                {
                    "stage": "router-egress",
                    "target": destination_ip,
                    "router": router_name,
                    "vrf": used_vrf,
                    "egress_interface": terminal_interface,
                    "subnet": route.get(
                        "prefix"
                    ),
                    "protocol": route_protocol,
                    "confidence": "high"
                }
            )

            return evidence

        #
        # A non-terminal route without a next-hop cannot
        # be traversed further from the available routing
        # evidence.
        #
        if not next_hop:
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
                    visited_routers=visited_routers,
                    visited_contexts=visited_contexts,
                    depth=depth + 1,
                    max_depth=max_depth
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

                #
                # The next routing scope belongs to the
                # resolved next-hop interface.  Preserve the
                # current VRF only as a fallback when the
                # normalized interface has no VRF information.
                #
                next_vrf = (
                    next_node.properties.get("vrf")
                    or used_vrf
                )

                evidence.extend(
                    self._trace_router_context(
                        destination_ip=destination_ip,
                        router_name=next_router,
                        vrf=next_vrf,
                        visited_routers=visited_routers,
                        visited_contexts=visited_contexts,
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
        # Destination-only route matches across multiple
        # routing tables cannot establish the forwarding
        # source context.  Never choose a VRF/device by
        # name, ordering or use-case preference.
        #
        contexts = {
            (
                item.get("router"),
                item.get("vrf")
            )
            for item in best
        }

        if len(contexts) != 1:
            return None

        return best[0]

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
                "direct",
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
        # Source resolution is a prerequisite for claiming
        # deterministic forwarding.  If the source side is
        # unresolved or ambiguous, do not reinterpret route
        # evidence as a valid end-to-end path.
        #
        source_failures = [
            item
            for item in evidence
            if item.get("stage") == "source-resolution"
            and item.get("source_resolution") in {
                "unresolved",
                "ambiguous",
                "incomplete",
                "unsupported",
                "unsupported-direction"
            }
        ]

        if source_failures:

            failure = source_failures[-1]

            return {
                "hint_type": "source-unresolved",
                "hint_value": None,
                "confidence": "low",
                "reason": failure.get(
                    "reason",
                    "Forwarding source could not be resolved"
                ),
                **forwarding
            }

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
        # 3. Routing loop.
        #
        # A detected traversal loop is different from
        # missing inventory. The managed path exists,
        # but forwarding returns to an already visited
        # firewall context.
        #
        routing_loops = [
            item
            for item in evidence
            if (
                item.get(
                    "stage"
                ) == "routing-loop"
                or item.get(
                    "routing_loop"
                )
            )
        ]

        if routing_loops:

            loop_contexts = []

            for item in routing_loops:

                context = item.get(
                    "context"
                )

                if (
                    context
                    and context not in loop_contexts
                ):

                    loop_contexts.append(
                        context
                    )

            if len(
                loop_contexts
            ) > 1:

                return {
                    "hint_type": "routing-loop",
                    "hint_value": None,
                    "confidence": "medium",
                    "reason": (
                        "Deterministic routing analysis "
                        "detected traversal loops in "
                        "multiple firewall contexts: "
                        + ", ".join(
                            loop_contexts
                        )
                    ),
                    **forwarding
                }

            loop = routing_loops[
                -1
            ]

            return {
                "hint_type": "routing-loop",
                "hint_value": loop.get(
                    "context"
                ),
                "confidence": loop.get(
                    "confidence",
                    "medium"
                ),
                "reason": (
                    "Deterministic routing path "
                    "entered a firewall traversal loop"
                    + (
                        f" at context "
                        f"{loop.get('context')}"
                        if loop.get(
                            "context"
                        )
                        else ""
                    )
                ),
                **forwarding
            }

        #
        # 4. Traversal safety limit.
        #
        # This does not mean inventory is missing.
        # The engine deliberately stopped recursive
        # traversal after reaching max_depth.
        #
        traversal_limits = [
            item
            for item in evidence
            if (
                item.get(
                    "stage"
                ) == "traversal-limit"
                or item.get(
                    "traversal_limit"
                )
            )
        ]

        if traversal_limits:

            limit_contexts = []

            for item in traversal_limits:

                context = item.get(
                    "context"
                )

                if (
                    context
                    and context not in limit_contexts
                ):

                    limit_contexts.append(
                        context
                    )

            limit = traversal_limits[
                -1
            ]

            return {
                "hint_type": "traversal-limit",
                "hint_value": (
                    limit_contexts[0]
                    if len(
                        limit_contexts
                    ) == 1
                    else None
                ),
                "confidence": limit.get(
                    "confidence",
                    "low"
                ),
                "reason": (
                    "Routing analysis reached the "
                    "maximum traversal depth"
                    + (
                        f" at firewall context "
                        f"{limit.get('context')}"
                        if limit.get(
                            "context"
                        )
                        else ""
                    )
                ),
                **forwarding
            }

        #
        # 5. Inventory boundary.
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
        # 6. Firewall context.
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
        # 7. Router-level evidence only.
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
        visited_routers=None,
        visited_contexts=None,
        depth=0,
        max_depth=8
    ):

        evidence = []

        if visited_routers is None:
            visited_routers = set()

        if visited_contexts is None:
            visited_contexts = set()

        #
        # Traversal safety limit.
        #
        # Reaching the maximum traversal depth is not an
        # inventory boundary. It means the engine stopped
        # because its deterministic traversal safety limit
        # was reached.
        #
        if depth > max_depth:

            evidence.append(
                {
                    "stage": "traversal-limit",
                    "target": destination_ip,
                    "context": firewall_context,
                    "traversal_limit": True,
                    "confidence": "low",
                    "reason": (
                        "Maximum firewall traversal "
                        "depth reached"
                    )
                }
            )

            return evidence

        #
        # Routing/traversal loop.
        #
        # A context that has already been visited is not an
        # inventory boundary. Inventory exists, but the
        # deterministic forwarding path has returned to an
        # already visited firewall context.
        #
        if firewall_context in visited_contexts:

            evidence.append(
                {
                    "stage": "routing-loop",
                    "target": destination_ip,
                    "context": firewall_context,
                    "routing_loop": True,
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
                        visited_routers=visited_routers,
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
                            visited_routers=visited_routers,
                            visited_contexts=visited_contexts,
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
                            visited_routers=visited_routers,
                            visited_contexts=visited_contexts,
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

