from engines.flow_aggregator import FlowAggregator
from engines.communication_classifier import CommunicationClassifier


class CommunicationModelEngine:

    def __init__(
        self,
        graph,
        object_resolver,
        endpoint_resolver,
        dependency_resolver=None
    ):
        self.graph = graph
        self.object_resolver = object_resolver
        self.endpoint_resolver = endpoint_resolver
        self.dependency_resolver = dependency_resolver
        self.flow_aggregator = FlowAggregator()
        self.classifier = CommunicationClassifier()


    def build(self, rules):

        aggregation = (
            self.flow_aggregator.aggregate(
                rules
            )
        )

        communications = []

        for pair in aggregation[
            "communication_pairs"
        ]:

            context = pair.get("context")

            source = self._resolve_side(
                pair.get("source"),
                context
            )

            destination = self._resolve_side(
                pair.get("destination"),
                context
            )

            communication = {
                "context": context,
                "source": source,
                "destination": destination,
                "services": pair.get(
                    "services",
                    []
                ),
                "logical_flows": pair.get(
                    "logical_flows",
                    0
                ),
                "evidence_count": pair.get(
                    "evidence_count",
                    0
                ),
                "hitcnt": pair.get(
                    "hitcnt"
                )
            }

            communication["classification"] = (
                self.classifier.classify(
                    communication
                )
            )

            communication[
                "infrastructure_dependencies"
            ] = self._collect_dependencies(
                source,
                destination
            )

            communications.append(
                communication
            )

        return {
            "summary": {
                "raw_rules": aggregation[
                    "summary"
                ]["raw_rules"],
                "logical_flows": aggregation[
                    "summary"
                ]["logical_flows"],
                "communication_pairs": len(
                    communications
                ),
                "resolved_sources": sum(
                    1
                    for x in communications
                    if x["source"]["resolved"]
                ),
                "resolved_destinations": sum(
                    1
                    for x in communications
                    if x["destination"]["resolved"]
                )
            },
            "communications": communications,
            "service_families": aggregation[
                "service_families"
            ]
        }


    def _resolve_side(
        self,
        value,
        context
    ):

        object_result = (
            self.object_resolver.resolve(
                value,
                context=context
            )
        )

        endpoints = []

        #
        # Resolve concrete hosts.
        #
        for host in object_result[
            "hosts"
        ]:

            endpoints.append(
                self._resolve_endpoint(
                    host
                )
            )

        #
        # Resolve concrete networks.
        #
        networks = []

        for network in object_result[
            "networks"
        ]:

            try:

                network_resolution = (
                    self.endpoint_resolver.resolve_network(
                        network
                    )
                )

            except Exception as exc:

                network_resolution = {
                    "found": False,
                    "network": network,
                    "confidence": "low",
                    "reason": str(exc)
                }

            networks.append({
                "network": network,
                "resolution": network_resolution
            })

        return {
            "reference": value,
            "resolved": object_result[
                "resolved"
            ],
            "hosts": object_result[
                "hosts"
            ],
            "networks": networks,
            "groups": object_result[
                "groups"
            ],
            "objects": object_result[
                "objects"
            ],
            "unresolved": object_result[
                "unresolved"
            ],
            "endpoints": endpoints
        }


    def _resolve_endpoint(
        self,
        endpoint
    ):

        endpoint_result = (
            self.endpoint_resolver.resolve(
                endpoint
            )
        )

        dependency_result = None

        if self.dependency_resolver:

            try:

                dependency_result = (
                    self.dependency_resolver.resolve_endpoint(
                        endpoint
                    )
                )

            except Exception as exc:

                dependency_result = {
                    "error": str(exc)
                }

        return {
            "endpoint": endpoint,
            "resolution": endpoint_result,
            "dependency": dependency_result
        }


    def _collect_dependencies(
        self,
        source,
        destination
    ):

        source_result = (
            self._new_dependency_bucket()
        )

        destination_result = (
            self._new_dependency_bucket()
        )

        combined_result = (
            self._new_dependency_bucket()
        )

        #
        # Source side only.
        #
        self._collect_side_dependencies(
            source,
            source_result,
            "source_evidence"
        )

        #
        # Destination side only.
        #
        self._collect_side_dependencies(
            destination,
            destination_result,
            "destination_evidence"
        )

        #
        # Combined footprint.
        #
        self._merge_dependency_bucket(
            combined_result,
            source_result
        )

        self._merge_dependency_bucket(
            combined_result,
            destination_result
        )

        return {
            "source_dependencies": (
                self._finalize_dependency_bucket(
                    source_result
                )
            ),
            "destination_dependencies": (
                self._finalize_dependency_bucket(
                    destination_result
                )
            ),
            "combined_dependencies": (
                self._finalize_dependency_bucket(
                    combined_result
                )
            )
        }

    def _new_dependency_bucket(self):

        return {
            "routers": set(),
            "firewalls": set(),
            "vrfs": set(),
            "contexts": set(),
            "interfaces": set(),
            "redundancy_groups": [],
            "route_owners": set(),
            "source_evidence": [],
            "destination_evidence": []
        }


    def _merge_dependency_bucket(
        self,
        target,
        source
    ):

        for key in [
            "routers",
            "firewalls",
            "vrfs",
            "contexts",
            "interfaces",
            "route_owners"
        ]:

            target[key].update(
                source[key]
            )

        target[
            "redundancy_groups"
        ].extend(
            source[
                "redundancy_groups"
            ]
        )

        target[
            "source_evidence"
        ].extend(
            source[
                "source_evidence"
            ]
        )

        target[
            "destination_evidence"
        ].extend(
            source[
                "destination_evidence"
            ]
        )


    def _finalize_dependency_bucket(
        self,
        result
    ):

        unique_redundancy = []
        seen = set()

        for group in result[
            "redundancy_groups"
        ]:

            members = tuple(
                sorted(
                    (
                        member.get("router"),
                        member.get("interface"),
                        member.get("ip"),
                        member.get("priority"),
                        member.get("vrf")
                    )
                    for member in group.get(
                        "members",
                        []
                    )
                )
            )

            key = (
                group.get("virtual_ip"),
                members
            )

            if key in seen:
                continue

            seen.add(key)

            unique_redundancy.append(
                group
            )

        return {
            "routers": sorted(
                result["routers"]
            ),
            "firewalls": sorted(
                result["firewalls"]
            ),
            "vrfs": sorted(
                result["vrfs"]
            ),
            "contexts": sorted(
                result["contexts"]
            ),
            "interfaces": sorted(
                result["interfaces"]
            ),
            "route_owners": sorted(
                result["route_owners"]
            ),
            "redundancy_groups": (
                unique_redundancy
            ),
            "source_evidence": (
                result["source_evidence"]
            ),
            "destination_evidence": (
                result["destination_evidence"]
            )
        }


    def _collect_side_dependencies(
        self,
        side,
        result,
        evidence_key
    ):

        #
        # Host endpoint dependencies.
        #
        for endpoint in side.get(
            "endpoints",
            []
        ):

            dependency = endpoint.get(
                "dependency"
            ) or {}

            for path in dependency.get(
                "dependencies",
                []
            ):

                #
                # Route owner.
                #
                owner = path.get(
                    "route_owner"
                )

                if owner:

                    result[
                        "route_owners"
                    ].add(owner)

                    self._add_device(
                        result,
                        owner
                    )

                #
                # VRF.
                #
                self._add_vrf(
                    result,
                    path.get("vrf")
                )

                #
                # Explicit routers.
                #
                for router in path.get(
                    "routers",
                    []
                ):

                    self._add_device(
                        result,
                        router
                    )

                #
                # Contexts.
                #
                for context in path.get(
                    "contexts",
                    []
                ):

                    if context:

                        result[
                            "contexts"
                        ].add(context)

                #
                # Interfaces.
                #
                for interface in path.get(
                    "interfaces",
                    []
                ):

                    name = interface.get(
                        "name"
                    )

                    if name:

                        result[
                            "interfaces"
                        ].add(name)

                    for device in interface.get(
                        "devices",
                        []
                    ):

                        self._add_device(
                            result,
                            device
                        )

                    for interface_vrf in interface.get(
                        "vrfs",
                        []
                    ):

                        self._add_vrf(
                            result,
                            interface_vrf
                        )

                    for context in interface.get(
                        "contexts",
                        []
                    ):

                        if context:

                            result[
                                "contexts"
                            ].add(context)

                #
                # Redundancy / HSRP evidence.
                #
                redundancy = path.get(
                    "redundancy",
                    []
                )

                if redundancy:

                    group = {
                        "virtual_ip": path.get(
                            "next_hop"
                        ),
                        "members": []
                    }

                    for member in redundancy:

                        member_entry = {
                            "router": member.get(
                                "router"
                            ),
                            "interface": member.get(
                                "interface"
                            ),
                            "ip": member.get(
                                "ip"
                            ),
                            "priority": member.get(
                                "priority"
                            ),
                            "vrf": member.get(
                                "vrf"
                            )
                        }

                        group[
                            "members"
                        ].append(
                            member_entry
                        )

                        router = member.get(
                            "router"
                        )

                        self._add_device(
                            result,
                            router
                        )

                        self._add_vrf(
                            result,
                            member.get("vrf")
                        )

                        interface_name = member.get(
                            "interface"
                        )

                        if (
                            router
                            and interface_name
                        ):

                            result[
                                "interfaces"
                            ].add(
                                f"{router}:{interface_name}"
                            )

                    result[
                        "redundancy_groups"
                    ].append(
                        group
                    )

            #
            # Endpoint evidence summary.
            #
            result[
                evidence_key
            ].append({
                "type": "host",
                "endpoint": endpoint.get(
                    "endpoint"
                ),
                "confidence": dependency.get(
                    "confidence"
                ),
                "paths": len(
                    dependency.get(
                        "dependencies",
                        []
                    )
                )
            })

        #
        # Network dependencies.
        #
        for item in side.get(
            "networks",
            []
        ):

            resolution = item.get(
                "resolution"
            ) or {}

            network = item.get(
                "network"
            )

            #
            # Connected infrastructure evidence.
            #
            for infra in resolution.get(
                "infrastructure",
                []
            ):

                name = infra.get(
                    "name"
                )

                if name:

                    result[
                        "interfaces"
                    ].add(name)

                for device in infra.get(
                    "devices",
                    []
                ):

                    self._add_device(
                        result,
                        device
                    )

                for vrf in infra.get(
                    "vrfs",
                    []
                ):

                    self._add_vrf(
                        result,
                        vrf
                    )

                for context in infra.get(
                    "contexts",
                    []
                ):

                    if context:

                        result[
                            "contexts"
                        ].add(context)

            #
            # Exact routing evidence.
            #
            for route in resolution.get(
                "exact_routes",
                []
            ):

                owner = (
                    route.get("router")
                    or route.get("device")
                )

                if owner:

                    result[
                        "route_owners"
                    ].add(owner)

                    self._add_device(
                        result,
                        owner
                    )

                vrf = (
                    route.get("vrf")
                    or route.get("context")
                )

                self._add_vrf(
                    result,
                    vrf
                )

                egress = (
                    route.get(
                        "egress_interface"
                    )
                    or route.get(
                        "interface"
                    )
                    or route.get(
                        "exit_interface"
                    )
                )

                if (
                    owner
                    and egress
                ):

                    result[
                        "interfaces"
                    ].add(
                        f"{owner}:{egress}"
                    )

            #
            # Network evidence summary.
            #
            result[
                evidence_key
            ].append({
                "type": "network",
                "network": network,
                "confidence": resolution.get(
                    "confidence"
                ),
                "exact_routes": len(
                    resolution.get(
                        "exact_routes",
                        []
                    )
                ),
                "infrastructure": len(
                    resolution.get(
                        "infrastructure",
                        []
                    )
                )
            })


    def _add_vrf(
        self,
        result,
        vrf
    ):

        if not vrf:
            return

        #
        # Only accept actual VRF nodes.
        #
        if self.graph.find(
            "VRF",
            vrf
        ):

            result[
                "vrfs"
            ].add(vrf)


    def _add_device(
        self,
        result,
        name
    ):

        if not name:
            return

        #
        # Classify actual graph devices.
        #
        if self.graph.find(
            "Router",
            name
        ):

            result[
                "routers"
            ].add(name)

            return

        if self.graph.find(
            "Firewall",
            name
        ):

            result[
                "firewalls"
            ].add(name)