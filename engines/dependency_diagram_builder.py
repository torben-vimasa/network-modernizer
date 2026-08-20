class DependencyDiagramBuilder:

    def __init__(
        self,
        flow_trace_engine=None,
        max_trace_pairs=16,
        aggregate_paths=True
    ):
        self.flow_trace_engine = (
            flow_trace_engine
        )

        self.max_trace_pairs = (
            max_trace_pairs
        )

        self.aggregate_paths = (
            aggregate_paths
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
            "skipped_expansion_limit": 0,
            "path_families": 0
        }

        app_id = (
            f"application:{application}"
        )

        nodes[app_id] = {
            "id": app_id,
            "type": "application",
            "label": application
        }

        trace_records = []

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

            if not self.flow_trace_engine:
                continue

            records = (
                self._collect_forwarding_traces(
                    communication=communication,
                    trace_stats=trace_stats
                )
            )

            trace_records.extend(
                records
            )

        path_families = []

        if self.flow_trace_engine:

            if self.aggregate_paths:

                path_families = (
                    self._add_path_families(
                        nodes=nodes,
                        edges=edges,
                        trace_records=trace_records
                    )
                )

            else:

                for record in trace_records:

                    self._add_trace(
                        nodes=nodes,
                        edges=edges,
                        app_id=app_id,
                        source_ip=record[
                            "source"
                        ],
                        destination_ip=record[
                            "destination"
                        ],
                        trace=record[
                            "trace"
                        ],
                        communication=record[
                            "communication"
                        ]
                    )

        trace_stats[
            "path_families"
        ] = len(
            path_families
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
                ),
                "path_families": len(
                    path_families
                )
            },

            "trace_stats": trace_stats,

            "path_families": (
                path_families
            ),

            "nodes": list(
                nodes.values()
            ),

            "edges": edges
        }


    def _collect_forwarding_traces(
        self,
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

        if (
            not source_hosts
            or not destination_hosts
        ):

            trace_stats[
                "skipped_no_hosts"
            ] += 1

            return []

        pair_count = (
            len(source_hosts)
            * len(destination_hosts)
        )

        trace_stats[
            "traceable"
        ] += 1

        if pair_count > self.max_trace_pairs:

            trace_stats[
                "skipped_expansion_limit"
            ] += 1

            return []

        result = []

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

                result.append({
                    "source": source_ip,
                    "destination": (
                        destination_ip
                    ),
                    "trace": trace,
                    "communication": (
                        communication
                    )
                })

        return result


    def _add_path_families(
        self,
        nodes,
        edges,
        trace_records
    ):

        grouped = {}

        for record in trace_records:

            trace = record.get(
                "trace",
                {}
            )

            paths = trace.get(
                "paths",
                []
            )

            for path in paths:

                signature = (
                    self._path_signature(
                        path
                    )
                )

                if not signature:
                    continue

                grouped.setdefault(
                    signature,
                    []
                ).append({
                    "source": record[
                        "source"
                    ],
                    "destination": record[
                        "destination"
                    ],
                    "trace": trace,
                    "path": path,
                    "communication": (
                        record[
                            "communication"
                        ]
                    )
                })

        families = []

        ordered_groups = sorted(
            grouped.items(),
            key=lambda item: (
                -len(item[1]),
                str(item[0])
            )
        )

        for index, (
            signature,
            records
        ) in enumerate(
            ordered_groups,
            start=1
        ):

            family = (
                self._build_family(
                    family_index=index,
                    signature=signature,
                    records=records
                )
            )

            families.append(
                family
            )

            self._add_family_nodes_and_edges(
                nodes=nodes,
                edges=edges,
                family=family,
                records=records
            )

        return families


    def _path_signature(
        self,
        path
    ):

        hops = path.get(
            "hops",
            []
        )

        if not hops:
            return None

        signature = []

        for hop in hops:

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

            signature.append(
                (
                    hop.get(
                        "device"
                    ),
                    hop.get(
                        "device_type"
                    ),
                    hop.get(
                        "vrf"
                    ),
                    route.get(
                        "protocol"
                    ),
                    route.get(
                        "next_hop"
                    ),
                    forwarding.get(
                        "device"
                    ),
                    forwarding.get(
                        "method"
                    ),
                    bool(
                        forwarding.get(
                            "inventory_boundary"
                        )
                    ),
                    hop.get(
                        "status"
                    )
                )
            )

        if path.get(
            "inventory_boundary"
        ):

            terminal = (
                "inventory_boundary",
                self._boundary_next_hop(
                    path
                )
            )

        elif path.get(
            "destination_reached"
        ):

            terminal = (
                "destination_reached",
            )

        else:

            terminal = (
                "unresolved",
                path.get(
                    "reason"
                )
            )

        return (
            tuple(signature),
            terminal
        )


    def _build_family(
        self,
        family_index,
        signature,
        records
    ):

        sources = sorted(
            {
                record[
                    "source"
                ]
                for record in records
            }
        )

        destinations = sorted(
            {
                record[
                    "destination"
                ]
                for record in records
            }
        )

        firewalls = sorted(
            {
                firewall
                for record in records
                for firewall in record[
                    "path"
                ].get(
                    "firewalls",
                    []
                )
            }
        )

        routers = sorted(
            {
                router
                for record in records
                for router in record[
                    "path"
                ].get(
                    "routers",
                    []
                )
            }
        )

        vrfs = sorted(
            {
                vrf
                for record in records
                for vrf in record[
                    "path"
                ].get(
                    "vrfs",
                    []
                )
            }
        )

        confidences = sorted(
            {
                record[
                    "trace"
                ].get(
                    "confidence"
                )
                for record in records
                if record[
                    "trace"
                ].get(
                    "confidence"
                )
            }
        )

        path = records[0][
            "path"
        ]

        terminal = (
            "inventory_boundary"
            if path.get(
                "inventory_boundary"
            )
            else (
                "destination_reached"
                if path.get(
                    "destination_reached"
                )
                else "unresolved"
            )
        )

        return {
            "id": (
                f"path_family:{family_index}"
            ),
            "index": family_index,
            "flow_count": len(records),
            "source_count": len(
                sources
            ),
            "destination_count": len(
                destinations
            ),
            "sources": sources,
            "destinations": (
                destinations
            ),
            "firewalls": firewalls,
            "routers": routers,
            "vrfs": vrfs,
            "confidence": confidences,
            "terminal": terminal,
            "signature": signature
        }


    def _add_family_nodes_and_edges(
        self,
        nodes,
        edges,
        family,
        records
    ):

        family_index = family[
            "index"
        ]

        source_id = (
            f"path_family:{family_index}:sources"
        )

        destination_id = (
            f"path_family:{family_index}:destinations"
        )

        nodes[source_id] = {
            "id": source_id,
            "type": "source_family",
            "label": self._family_endpoint_label(
                family[
                    "sources"
                ],
                "source"
            ),
            "member_count": (
                family[
                    "source_count"
                ]
            ),
            "members": (
                family[
                    "sources"
                ]
            ),
            "path_family": (
                family[
                    "id"
                ]
            )
        }

        nodes[destination_id] = {
            "id": destination_id,
            "type": "destination_family",
            "label": self._family_endpoint_label(
                family[
                    "destinations"
                ],
                "destination"
            ),
            "member_count": (
                family[
                    "destination_count"
                ]
            ),
            "members": (
                family[
                    "destinations"
                ]
            ),
            "path_family": (
                family[
                    "id"
                ]
            )
        }

        representative = records[0][
            "path"
        ]

        hops = representative.get(
            "hops",
            []
        )

        previous_id = (
            source_id
        )

        for hop_index, hop in enumerate(
            hops,
            start=1
        ):

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

            aggregate = (
                self._aggregate_hop(
                    records,
                    hop_index - 1
                )
            )

            properties = {
                "path_family": (
                    family[
                        "id"
                    ]
                ),
                "flow_count": (
                    family[
                        "flow_count"
                    ]
                ),
                "vrf": aggregate.get(
                    "vrf"
                ),
                "prefixes": aggregate.get(
                    "prefixes",
                    []
                ),
                "protocols": aggregate.get(
                    "protocols",
                    []
                ),
                "next_hop": aggregate.get(
                    "next_hop"
                ),
                "forwarding_method": (
                    aggregate.get(
                        "forwarding_method"
                    )
                ),
                "status": aggregate.get(
                    "status"
                )
            }

            self._add_edge(
                edges,
                previous_id,
                device_id,
                "forwarding_path",
                properties=properties
            )

            previous_id = (
                device_id
            )

        if representative.get(
            "inventory_boundary"
        ):

            next_hop = (
                self._boundary_next_hop(
                    representative
                )
                or "unknown"
            )

            boundary_id = (
                "inventory_boundary:"
                f"{family_index}:"
                f"{next_hop}"
            )

            nodes[boundary_id] = {
                "id": boundary_id,
                "type": (
                    "inventory_boundary"
                ),
                "label": (
                    "Inventory boundary"
                    f"<br/>{next_hop}"
                ),
                "next_hop": next_hop,
                "path_family": (
                    family[
                        "id"
                    ]
                )
            }

            self._add_edge(
                edges,
                previous_id,
                boundary_id,
                "inventory_boundary",
                properties={
                    "path_family": (
                        family[
                            "id"
                        ]
                    ),
                    "flow_count": (
                        family[
                            "flow_count"
                        ]
                    ),
                    "next_hop": (
                        next_hop
                    )
                }
            )

            self._add_edge(
                edges,
                boundary_id,
                destination_id,
                "external_destination",
                properties={
                    "path_family": (
                        family[
                            "id"
                        ]
                    ),
                    "flow_count": (
                        family[
                            "flow_count"
                        ]
                    ),
                    "confidence": (
                        self._family_confidence(
                            records
                        )
                    )
                }
            )

        elif representative.get(
            "destination_reached"
        ):

            self._add_edge(
                edges,
                previous_id,
                destination_id,
                "destination_reached",
                properties={
                    "path_family": (
                        family[
                            "id"
                        ]
                    ),
                    "flow_count": (
                        family[
                            "flow_count"
                        ]
                    ),
                    "confidence": (
                        self._family_confidence(
                            records
                        )
                    )
                }
            )


    def _aggregate_hop(
        self,
        records,
        hop_index
    ):

        vrfs = set()
        prefixes = set()
        protocols = set()
        next_hops = set()
        methods = set()
        statuses = set()

        for record in records:

            hops = record[
                "path"
            ].get(
                "hops",
                []
            )

            if hop_index >= len(hops):
                continue

            hop = hops[
                hop_index
            ]

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

            if hop.get(
                "vrf"
            ):
                vrfs.add(
                    hop.get(
                        "vrf"
                    )
                )

            if route.get(
                "prefix"
            ):
                prefixes.add(
                    route.get(
                        "prefix"
                    )
                )

            if route.get(
                "protocol"
            ):
                protocols.add(
                    route.get(
                        "protocol"
                    )
                )

            if route.get(
                "next_hop"
            ):
                next_hops.add(
                    route.get(
                        "next_hop"
                    )
                )

            if forwarding.get(
                "method"
            ):
                methods.add(
                    forwarding.get(
                        "method"
                    )
                )

            if hop.get(
                "status"
            ):
                statuses.add(
                    hop.get(
                        "status"
                    )
                )

        return {
            "vrf": (
                next(iter(vrfs))
                if len(vrfs) == 1
                else None
            ),
            "prefixes": sorted(
                prefixes
            ),
            "protocols": sorted(
                protocols
            ),
            "next_hop": (
                next(iter(next_hops))
                if len(next_hops) == 1
                else None
            ),
            "forwarding_method": (
                next(iter(methods))
                if len(methods) == 1
                else None
            ),
            "status": (
                next(iter(statuses))
                if len(statuses) == 1
                else None
            )
        }


    def _boundary_next_hop(
        self,
        path
    ):

        for hop in reversed(
            path.get(
                "hops",
                []
            )
        ):

            forwarding = (
                hop.get(
                    "forwarding"
                )
                or {}
            )

            if forwarding.get(
                "inventory_boundary"
            ):

                route = (
                    hop.get(
                        "route"
                    )
                    or {}
                )

                return route.get(
                    "next_hop"
                )

        return None


    def _family_endpoint_label(
        self,
        members,
        role
    ):

        count = len(
            members
        )

        if count == 1:

            return (
                f"{members[0]}"
                f"<br/>{role}"
            )

        preview = members[
            :3
        ]

        label = (
            f"{count} {role}s"
        )

        for member in preview:

            label += (
                f"<br/>{member}"
            )

        if count > len(preview):

            label += (
                f"<br/>+{count-len(preview)} more"
            )

        return label


    def _family_confidence(
        self,
        records
    ):

        values = [
            record[
                "trace"
            ].get(
                "confidence"
            )
            for record in records
        ]

        if values and all(
            value == "high"
            for value in values
        ):
            return "high"

        if any(
            value in [
                "high",
                "medium"
            ]
            for value in values
        ):
            return "medium"

        return "low"


    #
    # Legacy per-trace rendering is retained
    # for troubleshooting and regression use.
    #
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

                previous_id = (
                    device_id
                )

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

        for host in side.get(
            "hosts",
            []
        ):

            if host:
                result.append(
                    str(host)
                )

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

        vrf_ids = []
        interface_ids = []

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

            self._add_edge(
                edges,
                app_id,
                node_id,
                "depends_on"
            )

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

            self._add_edge(
                edges,
                app_id,
                node_id,
                "depends_on"
            )

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

        for vrf_id in vrf_ids:

            self._add_edge(
                edges,
                app_id,
                vrf_id,
                "depends_on"
            )

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
            ),
            properties.get(
                "path_family"
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
                ),
                existing_properties.get(
                    "path_family"
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
