import ipaddress


class FlowTraceEngine:

    MAX_HOPS = 16

    def __init__(
        self,
        graph,
        endpoint_resolver,
        route_engine,
        forwarding_engine,
        firewall_routes=None,
        dependency_resolver=None
    ):
        self.graph = graph
        self.endpoint_resolver = endpoint_resolver
        self.route_engine = route_engine
        self.forwarding_engine = forwarding_engine
        self.firewall_routes = firewall_routes or []
        self.dependency_resolver = dependency_resolver


    def trace(
        self,
        source,
        destination
    ):

        source_resolution = (
            self.endpoint_resolver.resolve(
                source
            )
        )

        destination_resolution = (
            self.endpoint_resolver.resolve(
                destination
            )
        )

        source_dependency = None
        destination_dependency = None

        if self.dependency_resolver:

            try:
                source_dependency = (
                    self.dependency_resolver.resolve_endpoint(
                        source
                    )
                )
            except Exception:
                source_dependency = None

            try:
                destination_dependency = (
                    self.dependency_resolver.resolve_endpoint(
                        destination
                    )
                )
            except Exception:
                destination_dependency = None

        source_attachments = (
            self._direct_attachments(
                source_resolution
            )
        )

        destination_attachments = (
            self._direct_attachments(
                destination_resolution
            )
        )

        #
        # We must start from infrastructure
        # directly attached to the source.
        #
        start_points = (
            self._build_start_points(
                source_attachments
            )
        )

        paths = []

        for start in start_points:

            path = self._trace_from_start(
                source=source,
                destination=destination,
                start=start,
                destination_attachments=(
                    destination_attachments
                )
            )

            paths.append(path)

        #
        # No managed source attachment.
        #
        if not paths:

            return {
                "found": False,
                "path_resolved": False,
                "destination_reached": False,
                "inventory_boundary": False,

                "source": source,
                "destination": destination,

                "source_resolution": (
                    source_resolution
                ),
                "destination_resolution": (
                    destination_resolution
                ),

                "source_dependency": (
                    source_dependency
                ),
                "destination_dependency": (
                    destination_dependency
                ),

                "source_attachments": (
                    source_attachments
                ),
                "destination_attachments": (
                    destination_attachments
                ),

                "paths": [],
                "candidate_paths": [],

                "selected_candidate": None,

                "firewalls": [],
                "common_firewalls": [],
                "routers": [],
                "vrfs": [],

                "confidence": "low",

                "reason": (
                    "No managed source attachment "
                    "could be resolved."
                )
            }

        successful_paths = [
            path
            for path in paths
            if path.get(
                "destination_reached"
            )
        ]

        usable_paths = (
            successful_paths
            if successful_paths
            else paths
        )

        firewalls = self._collect_path_values(
            usable_paths,
            "firewalls"
        )

        routers = self._collect_path_values(
            usable_paths,
            "routers"
        )

        vrfs = self._collect_path_values(
            usable_paths,
            "vrfs"
        )

        common_firewalls = (
            self._common_values(
                usable_paths,
                "firewalls"
            )
        )

        selected_candidate = None

        if len(successful_paths) == 1:
            selected_candidate = 1

        confidence = (
            self._confidence(
                source_resolution,
                destination_resolution,
                successful_paths,
                paths
            )
        )

        #
        # V2 path-state semantics.
        #
        path_resolved = bool(
            paths
        )

        destination_reached = bool(
            successful_paths
        )

        inventory_boundary = any(
            path.get(
                "inventory_boundary"
            )
            for path in paths
        )

        return {
            #
            # "found" remains for compatibility,
            # but now means that a source-anchored
            # path could be resolved.
            #
            "found": path_resolved,

            "path_resolved": (
                path_resolved
            ),

            "destination_reached": (
                destination_reached
            ),

            "inventory_boundary": (
                inventory_boundary
            ),

            "source": source,
            "destination": destination,

            "source_resolution": (
                source_resolution
            ),
            "destination_resolution": (
                destination_resolution
            ),

            "source_dependency": (
                source_dependency
            ),
            "destination_dependency": (
                destination_dependency
            ),

            "source_attachments": (
                source_attachments
            ),
            "destination_attachments": (
                destination_attachments
            ),

            #
            # V2 native path model.
            #
            "paths": paths,

            #
            # Compatibility with V1 consumers.
            #
            "candidate_paths": paths,

            "selected_candidate": (
                selected_candidate
            ),

            "firewalls": firewalls,

            "common_firewalls": (
                common_firewalls
            ),

            "routers": routers,

            "vrfs": vrfs,

            "confidence": confidence,

            "reason": self._reason(
                successful_paths,
                paths
            )
        }

    def _trace_from_start(
        self,
        source,
        destination,
        start,
        destination_attachments
    ):

        current_device = start.get(
            "device"
        )

        current_scope = start.get(
            "scope"
        )

        hops = []

        firewalls = []
        routers = []
        vrfs = []

        visited = set()

        destination_reached = False
        inventory_boundary = False
        stop_reason = None

        for hop_number in range(
            1,
            self.MAX_HOPS + 1
        ):

            state = (
                current_device,
                current_scope
            )

            if state in visited:

                stop_reason = (
                    "Forwarding loop detected at "
                    f"{current_device} / "
                    f"{current_scope}"
                )

                break

            visited.add(state)

            device_type = (
                self._device_type(
                    current_device
                )
            )

            if device_type == "firewall":

                firewalls.append(
                    current_device
                )

            elif device_type == "router":

                routers.append(
                    current_device
                )

            if current_scope:
                vrfs.append(
                    current_scope
                )

            route_result = (
                self._lookup_route(
                    current_device,
                    current_scope,
                    destination
                )
            )

            if not route_result:

                hops.append({
                    "hop": hop_number,
                    "device": current_device,
                    "device_type": (
                        device_type
                    ),
                    "vrf": current_scope,
                    "route": None,
                    "forwarding": None,
                    "status": "no_route"
                })

                stop_reason = (
                    "No route to destination "
                    f"{destination} on "
                    f"{current_device} "
                    f"scope={current_scope}"
                )

                break

            route = route_result[
                "route"
            ]

            route_scope = route.get(
                "vrf"
            )

            if route_scope:
                current_scope = (
                    route_scope
                )

                vrfs.append(
                    route_scope
                )

            protocol = str(
                route.get(
                    "protocol"
                )
                or ""
            ).lower()

            prefix = route.get(
                "prefix"
            )

            next_hop = route.get(
                "next_hop"
            )

            #
            # Connected/direct/local means the
            # destination network has been reached.
            #
            if protocol in [
                "connected",
                "direct",
                "local"
            ]:

                hops.append({
                    "hop": hop_number,
                    "device": current_device,
                    "device_type": (
                        device_type
                    ),
                    "vrf": current_scope,
                    "route": route,
                    "forwarding": None,
                    "status": (
                        "destination_network_reached"
                    )
                })

                destination_reached = True

                stop_reason = (
                    "Destination network reached "
                    f"on {current_device} via "
                    f"{prefix}"
                )

                break

            #
            # No next-hop on a non-connected route.
            #
            if not next_hop:

                hops.append({
                    "hop": hop_number,
                    "device": current_device,
                    "device_type": (
                        device_type
                    ),
                    "vrf": current_scope,
                    "route": route,
                    "forwarding": None,
                    "status": "no_next_hop"
                })

                stop_reason = (
                    "Route exists but has no "
                    "resolvable next-hop."
                )

                break

            forwarding = (
                self.forwarding_engine.resolve_next_hop(
                    current_device,
                    next_hop
                )
            )

            forwarding_data = (
                self._forwarding_to_dict(
                    forwarding
                )
            )

            hops.append({
                "hop": hop_number,
                "device": current_device,
                "device_type": (
                    device_type
                ),
                "vrf": current_scope,
                "route": route,
                "forwarding": (
                    forwarding_data
                ),
                "status": (
                    "forward"
                    if forwarding_data.get(
                        "resolved"
                    )
                    else "unresolved_next_hop"
                )
            })

            if forwarding_data.get(
                "inventory_boundary"
            ):

                inventory_boundary = True

                stop_reason = (
                    forwarding_data.get(
                        "reason"
                    )
                )

                break

            if not forwarding_data.get(
                "resolved"
            ):

                stop_reason = (
                    forwarding_data.get(
                        "reason"
                    )
                    or (
                        "Unable to resolve "
                        f"next-hop {next_hop}"
                    )
                )

                break

            next_device = (
                forwarding_data.get(
                    "device"
                )
            )

            next_interface = (
                forwarding_data.get(
                    "interface"
                )
            )

            if not next_device:

                stop_reason = (
                    "Forwarding resolved without "
                    "a next managed device."
                )

                break

            #
            # VRF/context of the receiving
            # interface becomes the routing
            # scope for the next hop.
            #
            next_scope = (
                self._interface_scope(
                    next_device,
                    next_interface
                )
            )

            current_device = (
                next_device
            )

            current_scope = (
                next_scope
            )

        else:

            stop_reason = (
                f"Maximum hop count "
                f"{self.MAX_HOPS} reached."
            )

        return {
            "source": source,
            "destination": destination,
            "start": start,
            "hops": hops,
            "destination_reached": (
                destination_reached
            ),
            "inventory_boundary": (
                inventory_boundary
            ),
            "firewalls": self._unique(
                firewalls
            ),
            "routers": self._unique(
                routers
            ),
            "vrfs": self._unique(
                vrfs
            ),
            "reason": stop_reason
        }


    def _lookup_route(
        self,
        device,
        scope,
        destination
    ):

        scopes = []

        if scope:
            scopes.append(
                scope
            )

        #
        # Device/context name is frequently
        # the routing-table identifier on ASA.
        #
        if device not in scopes:
            scopes.append(
                device
            )

        #
        # First try explicit/current scopes.
        #
        for candidate_scope in scopes:

            route = (
                self._lookup_route_exact(
                    device,
                    candidate_scope,
                    destination
                )
            )

            if route:

                return {
                    "scope": candidate_scope,
                    "route": route
                }

        #
        # If the incoming interface did not
        # provide scope information, inspect all
        # route tables owned by this device.
        #
        candidates = (
            self._routes_for_device(
                device,
                destination
            )
        )

        if not candidates:
            return None

        #
        # Find best prefix length.
        #
        best_prefix = max(
            item["prefix_length"]
            for item in candidates
        )

        candidates = [
            item
            for item in candidates
            if item[
                "prefix_length"
            ] == best_prefix
        ]

        #
        # Prefer lowest administrative distance.
        #
        best_ad = min(
            item["admin_distance"]
            for item in candidates
        )

        candidates = [
            item
            for item in candidates
            if item[
                "admin_distance"
            ] == best_ad
        ]

        #
        # Prefer lowest metric.
        #
        best_metric = min(
            item["metric"]
            for item in candidates
        )

        candidates = [
            item
            for item in candidates
            if item[
                "metric"
            ] == best_metric
        ]

        #
        # Conservative:
        # only select if remaining candidates
        # represent the same logical route.
        #
        unique_routes = {}

        for item in candidates:

            route = item["route"]

            key = (
                route.get("vrf"),
                route.get("prefix"),
                route.get("next_hop"),
                route.get("protocol")
            )

            unique_routes[key] = item

        if len(unique_routes) != 1:
            return None

        return list(
            unique_routes.values()
        )[0]


    def _lookup_route_exact(
        self,
        device,
        scope,
        destination
    ):

        candidates = []

        for route in self._all_routes():

            route = (
                self._route_to_dict(
                    route
                )
            )

            if route.get(
                "router"
            ) != device:
                continue

            if route.get(
                "vrf"
            ) != scope:
                continue

            prefix = route.get(
                "prefix"
            )

            if not prefix:
                continue

            try:

                network = (
                    ipaddress.ip_network(
                        prefix,
                        strict=False
                    )
                )

                destination_ip = (
                    ipaddress.ip_address(
                        destination
                    )
                )

            except ValueError:
                continue

            if destination_ip not in network:
                continue

            candidates.append({
                "prefix_length": (
                    network.prefixlen
                ),
                "admin_distance": (
                    self._admin_distance(
                        route
                    )
                ),
                "metric": (
                    route.get(
                        "metric"
                    )
                    if route.get(
                        "metric"
                    ) is not None
                    else 0
                ),
                "route": route
            })

        if not candidates:
            return None

        best_prefix = max(
            item["prefix_length"]
            for item in candidates
        )

        candidates = [
            item
            for item in candidates
            if item[
                "prefix_length"
            ] == best_prefix
        ]

        best_ad = min(
            item["admin_distance"]
            for item in candidates
        )

        candidates = [
            item
            for item in candidates
            if item[
                "admin_distance"
            ] == best_ad
        ]

        best_metric = min(
            item["metric"]
            for item in candidates
        )

        candidates = [
            item
            for item in candidates
            if item[
                "metric"
            ] == best_metric
        ]

        #
        # Duplicate static/runtime entries
        # are collapsed here.
        #
        unique = {}

        for item in candidates:

            route = item["route"]

            key = (
                route.get("router"),
                route.get("vrf"),
                route.get("prefix"),
                route.get("next_hop"),
                route.get("protocol")
            )

            unique[key] = route

        if len(unique) != 1:
            return None

        return list(
            unique.values()
        )[0]


    def _routes_for_device(
        self,
        device,
        destination
    ):

        result = []

        destination_ip = (
            ipaddress.ip_address(
                destination
            )
        )

        for item in self._all_routes():

            route = (
                self._route_to_dict(
                    item
                )
            )

            if route.get(
                "router"
            ) != device:
                continue

            prefix = route.get(
                "prefix"
            )

            if not prefix:
                continue

            try:

                network = (
                    ipaddress.ip_network(
                        prefix,
                        strict=False
                    )
                )

            except ValueError:
                continue

            if destination_ip not in network:
                continue

            result.append({
                "scope": route.get(
                    "vrf"
                ),
                "prefix_length": (
                    network.prefixlen
                ),
                "admin_distance": (
                    self._admin_distance(
                        route
                    )
                ),
                "metric": (
                    route.get(
                        "metric"
                    )
                    if route.get(
                        "metric"
                    ) is not None
                    else 0
                ),
                "route": route
            })

        return result


    def _all_routes(self):

        return (
            list(
                self.route_engine.routes
            )
            + list(
                self.firewall_routes
            )
        )


    def _route_to_dict(
        self,
        route
    ):

        if isinstance(
            route,
            dict
        ):
            return dict(route)

        return {
            "router": getattr(
                route,
                "router",
                None
            ),
            "vrf": getattr(
                route,
                "vrf",
                None
            ),
            "prefix": getattr(
                route,
                "prefix",
                None
            ),
            "next_hop": getattr(
                route,
                "next_hop",
                None
            ),
            "protocol": getattr(
                route,
                "protocol",
                None
            ),
            "interface": getattr(
                route,
                "interface",
                None
            ),
            "egress_interface": getattr(
                route,
                "egress_interface",
                None
            ),
            "metric": getattr(
                route,
                "metric",
                None
            ),
            "admin_distance": getattr(
                route,
                "admin_distance",
                None
            )
        }


    def _admin_distance(
        self,
        route
    ):

        value = route.get(
            "admin_distance"
        )

        if value is not None:
            return value

        protocol = str(
            route.get(
                "protocol"
            )
            or ""
        ).lower()

        values = {
            "connected": 0,
            "local": 0,
            "direct": 0,
            "static": 1,
            "ebgp": 20,
            "bgp": 20,
            "eigrp": 90,
            "ospf": 110,
            "rip": 120,
            "ibgp": 200
        }

        return values.get(
            protocol,
            255
        )


    def _direct_attachments(
        self,
        resolution
    ):

        result = []

        for infra in resolution.get(
            "infrastructure",
            []
        ):

            if infra.get(
                "role"
            ) not in [
                "direct",
                "connected"
            ]:
                continue

            result.append(
                infra
            )

        return result


    def _build_start_points(
        self,
        attachments
    ):

        result = []
        seen = set()

        for attachment in attachments:

            devices = attachment.get(
                "devices",
                []
            )

            scopes = (
                attachment.get(
                    "vrfs",
                    []
                )
                + attachment.get(
                    "contexts",
                    []
                )
            )

            for device in devices:

                if not scopes:

                    scopes_for_device = [
                        device
                    ]

                else:

                    scopes_for_device = (
                        scopes
                    )

                for scope in scopes_for_device:

                    key = (
                        device,
                        scope
                    )

                    if key in seen:
                        continue

                    seen.add(key)

                    result.append({
                        "device": device,
                        "scope": scope,
                        "interface": (
                            attachment.get(
                                "interface"
                            )
                        ),
                        "ip": attachment.get(
                            "ip"
                        ),
                        "type": attachment.get(
                            "type"
                        )
                    })

        return result


    def _interface_scope(
        self,
        device,
        interface
    ):

        if not interface:
            return device

        #
        # ForwardingResult may contain either
        # short interface name or graph node name.
        #
        for node in self.graph.nodes.values():

            if node.type not in [
                "RouterInterface",
                "ASAInterface",
                "Interface"
            ]:
                continue

            node_interface = (
                node.properties.get(
                    "interface"
                )
                or node.properties.get(
                    "nameif"
                )
            )

            if (
                node.name != interface
                and node_interface != interface
            ):
                continue

            parent = (
                self._parent_device(
                    node
                )
            )

            if not parent:
                continue

            if parent.name != device:
                continue

            vrf = node.properties.get(
                "vrf"
            )

            if vrf:
                return vrf

            context = node.properties.get(
                "context"
            )

            if context:
                return context

            #
            # Some normalized ASA interfaces
            # use their context/device name
            # as routing scope.
            #
            return device

        return device


    def _parent_device(
        self,
        interface_node
    ):

        for relation, neighbor in (
            self.graph.neighbors(
                interface_node.id
            )
        ):

            if relation != "HAS_INTERFACE":
                continue

            if neighbor.type in [
                "Router",
                "Firewall",
                "Switch",
                "Context"
            ]:
                return neighbor

        return None


    def _device_type(
        self,
        device
    ):

        if not device:
            return None

        if self.graph.find(
            "Firewall",
            device
        ):
            return "firewall"

        #
        # ASA multi-context graph nodes can
        # represent the forwarding firewall.
        #
        if self.graph.find(
            "Context",
            device
        ):
            return "firewall"

        if self.graph.find(
            "Router",
            device
        ):
            return "router"

        if self.graph.find(
            "Switch",
            device
        ):
            return "switch"

        return None


    def _forwarding_to_dict(
        self,
        result
    ):

        if result is None:
            return {
                "resolved": False,
                "method": "none",
                "reason": (
                    "Forwarding engine "
                    "returned no result."
                )
            }

        return {
            "resolved": getattr(
                result,
                "resolved",
                False
            ),
            "method": getattr(
                result,
                "method",
                None
            ),
            "device": getattr(
                result,
                "device",
                None
            ),
            "device_type": getattr(
                result,
                "device_type",
                None
            ),
            "interface": getattr(
                result,
                "interface",
                None
            ),
            "inventory_boundary": getattr(
                result,
                "inventory_boundary",
                False
            ),
            "candidates": getattr(
                result,
                "candidates",
                []
            ),
            "reason": getattr(
                result,
                "reason",
                None
            )
        }


    def _collect_path_values(
        self,
        paths,
        key
    ):

        values = []

        for path in paths:

            values.extend(
                path.get(
                    key,
                    []
                )
            )

        return self._unique(
            values
        )


    def _common_values(
        self,
        paths,
        key
    ):

        if not paths:
            return []

        sets = [
            set(
                path.get(
                    key,
                    []
                )
            )
            for path in paths
        ]

        common = sets[0]

        for values in sets[1:]:

            common = (
                common.intersection(
                    values
                )
            )

        return sorted(
            common
        )


    def _confidence(
        self,
        source_resolution,
        destination_resolution,
        successful_paths,
        all_paths
    ):

        #
        # Nothing could be traced from the source.
        #
        if not all_paths:
            return "low"

        #
        # Full forwarding path reached
        # destination network.
        #
        if successful_paths:

            if (
                source_resolution.get(
                    "confidence"
                ) == "high"
                and
                destination_resolution.get(
                    "confidence"
                ) == "high"
            ):
                return "high"

            return "medium"

        #
        # We have a deterministic managed path,
        # but inventory ends before destination.
        #
        if any(
            path.get(
                "inventory_boundary"
            )
            for path in all_paths
        ):
            return "medium"

        #
        # Path stopped because of ambiguity,
        # missing route, unresolved next-hop,
        # loop, etc.
        #
        return "low"


    def _reason(
        self,
        successful_paths,
        all_paths
    ):

        #
        # Exactly one complete path.
        #
        if len(successful_paths) == 1:

            return (
                "A source-anchored forwarding "
                "path reached the destination."
            )

        #
        # Multiple complete paths.
        #
        if len(successful_paths) > 1:

            return (
                f"{len(successful_paths)} "
                "source-anchored forwarding "
                "paths reached the destination."
            )

        #
        # Managed topology ended before
        # destination, but the path up to the
        # boundary was deterministic.
        #
        if any(
            path.get(
                "inventory_boundary"
            )
            for path in all_paths
        ):

            return (
                "A deterministic forwarding path "
                "was resolved up to an inventory "
                "boundary."
            )

        #
        # We had one or more start paths,
        # but forwarding could not be completed.
        #
        return (
            f"{len(all_paths)} source-anchored "
            "path(s) were evaluated, but none "
            "reached the destination."
        )


    def _unique(
        self,
        values
    ):

        result = []
        seen = set()

        for value in values:

            if not value:
                continue

            if value in seen:
                continue

            seen.add(value)
            result.append(value)

        return result