class DependencyDiagramBuilder:

    def __init__(
        self,
        flow_trace_engine=None,
        max_trace_pairs=16
    ):
        self.flow_trace_engine = (
            flow_trace_engine
        )

        self.max_trace_pairs = (
            max_trace_pairs
        )


    def build(
        self,
        application_model
    ):

        application = (
            application_model.get(
                "application"
            )
            or "Unknown"
        )

        communications = (
            application_model.get(
                "communication",
                {}
            ).get(
                "communications",
                []
            )
        )

        nodes = {}
        edges = []

        trace_stats = {
            "communications": 0,
            "traceable": 0,
            "traced": 0,
            "successful": 0,
            "inventory_boundaries": 0,
            "skipped_no_hosts": 0,
            "skipped_expansion_limit": 0
        }

        app_id = (
            f"application:{application}"
        )

        nodes[app_id] = {
            "id": app_id,
            "type": "application",
            "label": application
        }

        for communication in communications:

            trace_stats[
                "communications"
            ] += 1

            #
            # Existing dependency footprint.
            #
            dependencies = (
                communication.get(
                    "infrastructure_dependencies",
                    {}
                )
            )

            combined = dependencies.get(
                "combined_dependencies",
                {}
            )

            self._add_dependency_nodes(
                nodes,
                edges,
                app_id,
                combined
            )

            #
            # Source-anchored forwarding paths.
            #
            if self.flow_trace_engine:

                self._add_forwarding_paths(
                    nodes=nodes,
                    edges=edges,
                    app_id=app_id,
                    communication=communication,
                    trace_stats=trace_stats
                )

        return {
            "application": application,

            "summary": {
                "nodes": len(nodes),
                "edges": len(edges),
                "communications": len(
                    communications
                ),
                "traces": trace_stats[
                    "traced"
                ],
                "successful_traces": (
                    trace_stats[
                        "successful"
                    ]
                ),
                "inventory_boundaries": (
                    trace_stats[
                        "inventory_boundaries"
                    ]
                )
            },

            "trace_stats": trace_stats,

            "nodes": list(
                nodes.values()
            ),

            "edges": edges
        }


    def _add_forwarding_paths(
        self,
        nodes,
        edges,
        app_id,
        communication,
        trace_stats
    ):

        source = communication.get(
            "source",
            {}
        )

        destination = communication.get(
            "destination",
            {}
        )

        source_hosts = (
            self._concrete_hosts(
                source
            )
        )

        destination_hosts = (
            self._concrete_hosts(
                destination
            )
        )

        #
        # FlowTrace requires concrete IP
        # endpoints. Do not invent hosts from
        # networks or object groups.
        #
        if (
            not source_hosts
            or not destination_hosts
        ):

            trace_stats[
                "skipped_no_hosts"
            ] += 1

            return

        pair_count = (
            len(source_hosts)
            * len(destination_hosts)
        )

        trace_stats[
            "traceable"
        ] += 1

        #
        # Avoid exploding large object groups
        # into hundreds/thousands of traces.
        #
        if pair_count > self.max_trace_pairs:

            trace_stats[
                "skipped_expansion_limit"
            ] += 1

            return

        for source_ip in source_hosts:

            for destination_ip in (
                destination_hosts
            ):

                try:

                    trace = (
                        self.flow_trace_engine.trace(
                            source_ip,
                            destination_ip
                        )
                    )

                except Exception:

                    #
                    # Diagram generation must not
                    # break the application model.
                    #
                    continue

                trace_stats[
                    "traced"
                ] += 1

                if trace.get(
                    "destination_reached"
                ):

                    trace_stats[
                        "successful"
                    ] += 1

                if trace.get(
                    "inventory_boundary"
                ):

                    trace_stats[
                        "inventory_boundaries"
                    ] += 1

                self._add_trace(
                    nodes=nodes,
                    edges=edges,
                    app_id=app_id,
                    source_ip=source_ip,
                    destination_ip=destination_ip,
                    trace=trace,
                    communication=communication
                )


    def _add_trace(
        self,
        nodes,
        edges,
        app_id,
        source_ip,
        destination_ip,
        trace,
        communication
    ):

        source_id = (
            f"endpoint:{source_ip}"
        )

        destination_id = (
            f"endpoint:{destination_ip}"
        )

        nodes.setdefault(
            source_id,
            {
                "id": source_id,
                "type": "endpoint",
                "label": source_ip,
                "role": "source"
            }
        )

        nodes.setdefault(
            destination_id,
            {
                "id": destination_id,
                "type": "endpoint",
                "label": destination_ip,
                "role": "destination"
            }
        )

        #
        # Application owns the communication.
        #
        self._add_edge(
            edges,
            app_id,
            source_id,
            "application_endpoint"
        )

        paths = trace.get(
            "paths",
            []
        )

        for path_index, path in enumerate(
            paths,
            start=1
        ):

            previous_id = (
                source_id
            )

            hops = path.get(
                "hops",
                []
            )

            for hop in hops:

                device = hop.get(
                    "device"
                )

                if not device:
                    continue

                device_type = (
                    hop.get(
                        "device_type"
                    )
                    or "device"
                )

                device_id = (
                    f"{device_type}:"
                    f"{device}"
                )

                nodes.setdefault(
                    device_id,
                    {
                        "id": device_id,
                        "type": device_type,
                        "label": device
                    }
                )

                #
                # Preserve actual route evidence
                # on the edge.
                #
                route = (
                    hop.get(
                        "route"
                    )
                    or {}
                )

                forwarding = (
                    hop.get(
                        "forwarding"
                    )
                    or {}
                )

                self._add_edge(
                    edges,
                    previous_id,
                    device_id,
                    "forwarding_path",
                    properties={
                        "path": path_index,
                        "vrf": hop.get(
                            "vrf"
                        ),
                        "prefix": route.get(
                            "prefix"
                        ),
                        "protocol": route.get(
                            "protocol"
                        ),
                        "next_hop": route.get(
                            "next_hop"
                        ),
                        "forwarding_method": (
                            forwarding.get(
                                "method"
                            )
                        ),
                        "status": hop.get(
                            "status"
                        ),
                        "source": source_ip,
                        "destination": (
                            destination_ip
                        )
                    }
                )

                #
                # Explicit VRF/context relation
                # from the actual hop.
                #
                vrf = hop.get(
                    "vrf"
                )

                if vrf:

                    vrf_id = (
                        f"vrf:{vrf}"
                    )

                    nodes.setdefault(
                        vrf_id,
                        {
                            "id": vrf_id,
                            "type": "vrf",
                            "label": vrf
                        }
                    )

                    self._add_edge(
                        edges,
                        device_id,
                        vrf_id,
                        "forwarding_vrf"
                    )

                previous_id = (
                    device_id
                )

                #
                # Inventory boundary is a real
                # terminal state in the trace.
                #
                if (
                    forwarding.get(
                        "inventory_boundary"
                    )
                ):

                    next_hop = (
                        route.get(
                            "next_hop"
                        )
                        or "unknown"
                    )

                    boundary_id = (
                        "inventory_boundary:"
                        f"{device}:"
                        f"{next_hop}"
                    )

                    nodes.setdefault(
                        boundary_id,
                        {
                            "id": boundary_id,
                            "type": (
                                "inventory_boundary"
                            ),
                            "label": (
                                f"Inventory boundary"
                                f"<br/>{next_hop}"
                            ),
                            "next_hop": next_hop,
                            "reason": (
                                forwarding.get(
                                    "reason"
                                )
                            )
                        }
                    )

                    self._add_edge(
                        edges,
                        previous_id,
                        boundary_id,
                        "inventory_boundary",
                        properties={
                            "next_hop": (
                                next_hop
                            ),
                            "source": source_ip,
                            "destination": (
                                destination_ip
                            )
                        }
                    )

                    previous_id = (
                        boundary_id
                    )

            #
            # Only connect to the destination
            # when FlowTrace actually reached
            # the destination network.
            #
            if path.get(
                "destination_reached"
            ):

                self._add_edge(
                    edges,
                    previous_id,
                    destination_id,
                    "destination_reached",
                    properties={
                        "source": source_ip,
                        "destination": (
                            destination_ip
                        ),
                        "confidence": (
                            trace.get(
                                "confidence"
                            )
                        )
                    }
                )

            #
            # If inventory boundary was reached,
            # destination remains logically known
            # but is NOT represented as managed
            # forwarding adjacency.
            #
            elif path.get(
                "inventory_boundary"
            ):

                self._add_edge(
                    edges,
                    previous_id,
                    destination_id,
                    "external_destination",
                    properties={
                        "source": source_ip,
                        "destination": (
                            destination_ip
                        ),
                        "confidence": (
                            trace.get(
                                "confidence"
                            )
                        )
                    }
                )


    def _concrete_hosts(
        self,
        side
    ):

        result = []

        #
        # ObjectResolver host results.
        #
        for host in side.get(
            "hosts",
            []
        ):

            if host:
                result.append(
                    str(host)
                )

        #
        # EndpointResolver results.
        #
        for endpoint in side.get(
            "endpoints",
            []
        ):

            value = endpoint.get(
                "endpoint"
            )

            if value:
                result.append(
                    str(value)
                )

        return self._unique(
            result
        )


    def _add_dependency_nodes(
        self,
        nodes,
        edges,
        app_id,
        dependencies
    ):

        firewall_ids = []
        router_ids = []
        vrf_ids = []
        interface_ids = []

        #
        # Firewalls
        #
        for name in dependencies.get(
            "firewalls",
            []
        ):

            node_id = (
                f"firewall:{name}"
            )

            nodes[node_id] = {
                "id": node_id,
                "type": "firewall",
                "label": name
            }

            firewall_ids.append(
                node_id
            )

            self._add_edge(
                edges,
                app_id,
                node_id,
                "depends_on"
            )

        #
        # Routers
        #
        for name in dependencies.get(
            "routers",
            []
        ):

            node_id = (
                f"router:{name}"
            )

            nodes[node_id] = {
                "id": node_id,
                "type": "router",
                "label": name
            }

            router_ids.append(
                node_id
            )

            self._add_edge(
                edges,
                app_id,
                node_id,
                "depends_on"
            )

        #
        # VRFs
        #
        for name in dependencies.get(
            "vrfs",
            []
        ):

            node_id = (
                f"vrf:{name}"
            )

            nodes[node_id] = {
                "id": node_id,
                "type": "vrf",
                "label": name
            }

            vrf_ids.append(
                node_id
            )

        #
        # Interfaces
        #
        for name in dependencies.get(
            "interfaces",
            []
        ):

            node_id = (
                f"interface:{name}"
            )

            nodes[node_id] = {
                "id": node_id,
                "type": "interface",
                "label": name
            }

            interface_ids.append(
                node_id
            )

        #
        # Redundancy groups
        #
        for group in dependencies.get(
            "redundancy_groups",
            []
        ):

            virtual_ip = group.get(
                "virtual_ip"
            )

            if not virtual_ip:
                continue

            node_id = (
                f"redundancy:"
                f"{virtual_ip}"
            )

            nodes[node_id] = {
                "id": node_id,
                "type": "redundancy",
                "label": virtual_ip
            }

            for member in group.get(
                "members",
                []
            ):

                router = member.get(
                    "router"
                )

                interface = member.get(
                    "interface"
                )

                if router:

                    router_id = (
                        f"router:{router}"
                    )

                    nodes.setdefault(
                        router_id,
                        {
                            "id": router_id,
                            "type": "router",
                            "label": router
                        }
                    )

                    self._add_edge(
                        edges,
                        node_id,
                        router_id,
                        "redundancy_member"
                    )

                if (
                    router
                    and interface
                ):

                    interface_name = (
                        f"{router}:"
                        f"{interface}"
                    )

                    interface_id = (
                        "interface:"
                        f"{interface_name}"
                    )

                    nodes.setdefault(
                        interface_id,
                        {
                            "id": (
                                interface_id
                            ),
                            "type": (
                                "interface"
                            ),
                            "label": (
                                interface_name
                            )
                        }
                    )

                    self._add_edge(
                        edges,
                        router_id,
                        interface_id,
                        "via_interface"
                    )

        #
        # VRF dependency footprint.
        #
        for vrf_id in vrf_ids:

            self._add_edge(
                edges,
                app_id,
                vrf_id,
                "depends_on"
            )

        #
        # Device/interface ownership.
        #
        for interface_id in (
            interface_ids
        ):

            owner = (
                self._interface_owner(
                    interface_id
                )
            )

            if not owner:
                continue

            firewall_id = (
                f"firewall:{owner}"
            )

            router_id = (
                f"router:{owner}"
            )

            if firewall_id in nodes:

                self._add_edge(
                    edges,
                    firewall_id,
                    interface_id,
                    "has_interface"
                )

            if router_id in nodes:

                self._add_edge(
                    edges,
                    router_id,
                    interface_id,
                    "has_interface"
                )


    def _interface_owner(
        self,
        interface_id
    ):

        value = (
            interface_id.removeprefix(
                "interface:"
            )
        )

        if ":" not in value:
            return None

        return value.split(
            ":",
            1
        )[0]


    def _add_edge(
        self,
        edges,
        source,
        target,
        edge_type,
        properties=None
    ):

        properties = (
            properties
            or {}
        )

        #
        # Structural identity.
        #
        key = (
            source,
            target,
            edge_type,
            properties.get(
                "path"
            ),
            properties.get(
                "source"
            ),
            properties.get(
                "destination"
            )
        )

        for edge in edges:

            existing_properties = (
                edge.get(
                    "properties",
                    {}
                )
            )

            existing_key = (
                edge.get(
                    "source"
                ),
                edge.get(
                    "target"
                ),
                edge.get(
                    "type"
                ),
                existing_properties.get(
                    "path"
                ),
                existing_properties.get(
                    "source"
                ),
                existing_properties.get(
                    "destination"
                )
            )

            if existing_key == key:
                return

        edge = {
            "source": source,
            "target": target,
            "type": edge_type
        }

        if properties:
            edge[
                "properties"
            ] = properties

        edges.append(
            edge
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

            seen.add(
                value
            )

            result.append(
                value
            )

        return result