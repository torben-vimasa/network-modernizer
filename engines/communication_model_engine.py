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

            context = pair.get(
                "context"
            )

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

            communication[
                "classification"
            ] = self.classifier.classify(
                communication
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
                    for item in communications
                    if item["source"]["resolved"]
                ),
                "resolved_destinations": sum(
                    1
                    for item in communications
                    if item[
                        "destination"
                    ]["resolved"]
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
        for host in object_result.get(
            "hosts",
            []
        ):

            endpoints.append(
                self._resolve_endpoint(
                    host
                )
            )

        #
        # Resolve concrete networks.
        #
        networks = []

        for network in object_result.get(
            "networks",
            []
        ):

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
            "resolved": object_result.get(
                "resolved",
                False
            ),
            "hosts": object_result.get(
                "hosts",
                []
            ),
            "networks": networks,
            "groups": object_result.get(
                "groups",
                []
            ),
            "objects": object_result.get(
                "objects",
                []
            ),
            "unresolved": object_result.get(
                "unresolved",
                []
            ),
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
            "infrastructure_relations": [],
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
            "infrastructure_relations"
        ].extend(
            source[
                "infrastructure_relations"
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
        seen_redundancy = set()

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

            if key in seen_redundancy:
                continue

            seen_redundancy.add(
                key
            )

            unique_redundancy.append(
                group
            )

        unique_relations = []
        seen_relations = set()

        for relation in result[
            "infrastructure_relations"
        ]:

            key = (
                relation.get("device"),
                relation.get("device_type"),
                relation.get("interface"),
                relation.get("vrf"),
                relation.get("context"),
                relation.get("subnet"),
                relation.get("protocol"),
                relation.get("next_hop"),
                relation.get("relation_source")
            )

            if key in seen_relations:
                continue

            seen_relations.add(
                key
            )

            unique_relations.append(
                relation
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
            "infrastructure_relations": (
                unique_relations
            ),
            "source_evidence": (
                result["source_evidence"]
            ),
            "destination_evidence": (
                result[
                    "destination_evidence"
                ]
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

            endpoint_ip = endpoint.get(
                "endpoint"
            )

            dependency = endpoint.get(
                "dependency"
            ) or {}

            for path in dependency.get(
                "dependencies",
                []
            ):

                owner = path.get(
                    "route_owner"
                )

                path_vrf = path.get(
                    "vrf"
                )

                path_contexts = path.get(
                    "contexts",
                    []
                )

                prefix = path.get(
                    "prefix"
                )

                protocol = path.get(
                    "protocol"
                )

                next_hop = path.get(
                    "next_hop"
                )

                #
                # Route owner.
                #
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
                    path_vrf
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
                for context in path_contexts:

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

                    interface_name = (
                        interface.get(
                            "interface"
                        )
                        or interface.get(
                            "name"
                        )
                    )

                    graph_name = interface.get(
                        "name"
                    )

                    if graph_name:

                        result[
                            "interfaces"
                        ].add(
                            graph_name
                        )

                    interface_devices = (
                        interface.get(
                            "devices",
                            []
                        )
                    )

                    interface_vrfs = (
                        interface.get(
                            "vrfs",
                            []
                        )
                    )

                    interface_contexts = (
                        interface.get(
                            "contexts",
                            []
                        )
                    )

                    #
                    # Devices owning interface.
                    #
                    for device in interface_devices:

                        self._add_device(
                            result,
                            device
                        )

                    #
                    # Interface VRFs.
                    #
                    for interface_vrf in interface_vrfs:

                        self._add_vrf(
                            result,
                            interface_vrf
                        )

                    #
                    # Interface contexts.
                    #
                    for context in interface_contexts:

                        if context:

                            result[
                                "contexts"
                            ].add(context)

                    #
                    # Preserve explicit device/interface
                    # relationship while evidence is intact.
                    #
                    relation_vrfs = (
                        interface_vrfs
                        or (
                            [path_vrf]
                            if path_vrf
                            else [None]
                        )
                    )

                    relation_contexts = (
                        interface_contexts
                        or path_contexts
                        or [None]
                    )

                    for device in interface_devices:

                        device_type = (
                            self._device_type(
                                device
                            )
                        )

                        for relation_vrf in relation_vrfs:

                            for relation_context in (
                                relation_contexts
                            ):

                                self._add_infrastructure_relation(
                                    result,
                                    device=device,
                                    device_type=device_type,
                                    interface=interface_name,
                                    vrf=relation_vrf,
                                    context=relation_context,
                                    subnet=prefix,
                                    protocol=protocol,
                                    next_hop=next_hop,
                                    endpoint=endpoint_ip,
                                    relation_source=(
                                        "dependency_path_interface"
                                    )
                                )

                #
                # If route owner exists but no explicit
                # interface relation was available, preserve
                # the route-level relation.
                #
                if (
                    owner
                    and not path.get(
                        "interfaces",
                        []
                    )
                ):

                    self._add_infrastructure_relation(
                        result,
                        device=owner,
                        device_type=(
                            self._device_type(
                                owner
                            )
                        ),
                        interface=None,
                        vrf=path_vrf,
                        context=(
                            path_contexts[0]
                            if path_contexts
                            else None
                        ),
                        subnet=prefix,
                        protocol=protocol,
                        next_hop=next_hop,
                        endpoint=endpoint_ip,
                        relation_source=(
                            "dependency_path_route"
                        )
                    )

                #
                # Redundancy / HSRP evidence.
                #
                redundancy = path.get(
                    "redundancy",
                    []
                )

                if redundancy:

                    group = {
                        "virtual_ip": next_hop,
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

                        member_vrf = member.get(
                            "vrf"
                        )

                        interface_name = member.get(
                            "interface"
                        )

                        self._add_device(
                            result,
                            router
                        )

                        self._add_vrf(
                            result,
                            member_vrf
                        )

                        if (
                            router
                            and interface_name
                        ):

                            result[
                                "interfaces"
                            ].add(
                                f"{router}:"
                                f"{interface_name}"
                            )

                        #
                        # Preserve router/interface/VRF
                        # relationship from HSRP evidence.
                        #
                        self._add_infrastructure_relation(
                            result,
                            device=router,
                            device_type=(
                                self._device_type(
                                    router
                                )
                            ),
                            interface=interface_name,
                            vrf=member_vrf,
                            context=None,
                            subnet=prefix,
                            protocol="redundancy",
                            next_hop=next_hop,
                            endpoint=endpoint_ip,
                            relation_source=(
                                "redundancy_member"
                            )
                        )

                    result[
                        "redundancy_groups"
                    ].append(
                        group
                    )

            #
            # Direct endpoint infrastructure can contain
            # additional explicit evidence even if dependency
            # resolver returned no routed path.
            #
            endpoint_resolution = endpoint.get(
                "resolution"
            ) or {}

            for infra in endpoint_resolution.get(
                "infrastructure",
                []
            ):

                self._collect_infrastructure_relation(
                    result,
                    infra,
                    subnet=endpoint_resolution.get(
                        "subnet"
                    ),
                    protocol=(
                        "connected"
                        if endpoint_resolution.get(
                            "method"
                        ) == "direct_subnet"
                        else None
                    ),
                    next_hop=None,
                    endpoint=endpoint_ip,
                    relation_source=(
                        "endpoint_infrastructure"
                    )
                )

            #
            # Endpoint evidence summary.
            #
            result[
                evidence_key
            ].append({
                "type": "host",
                "endpoint": endpoint_ip,
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
                # Preserve explicit infrastructure relation.
                #
                self._collect_infrastructure_relation(
                    result,
                    infra,
                    subnet=network,
                    protocol="connected",
                    next_hop=None,
                    endpoint=None,
                    relation_source=(
                        "network_infrastructure"
                    )
                )

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
                # Preserve route-level relationship.
                #
                self._add_infrastructure_relation(
                    result,
                    device=owner,
                    device_type=(
                        self._device_type(
                            owner
                        )
                    ),
                    interface=egress,
                    vrf=vrf,
                    context=route.get(
                        "context"
                    ),
                    subnet=route.get(
                        "prefix",
                        network
                    ),
                    protocol=route.get(
                        "protocol"
                    ),
                    next_hop=route.get(
                        "next_hop"
                    ),
                    endpoint=None,
                    relation_source=(
                        "exact_route"
                    )
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


    def _collect_infrastructure_relation(
        self,
        result,
        infrastructure,
        subnet=None,
        protocol=None,
        next_hop=None,
        endpoint=None,
        relation_source=None
    ):

        interface_name = (
            infrastructure.get(
                "interface"
            )
            or infrastructure.get(
                "nameif"
            )
            or infrastructure.get(
                "name"
            )
        )

        devices = infrastructure.get(
            "devices",
            []
        )

        vrfs = infrastructure.get(
            "vrfs",
            []
        )

        contexts = infrastructure.get(
            "contexts",
            []
        )

        #
        # Some infrastructure dictionaries expose
        # the owner in their properties rather than
        # in the normalized devices list.
        #
        properties = infrastructure.get(
            "properties",
            {}
        )

        property_device = (
            properties.get("device")
            or properties.get("router")
        )

        if (
            property_device
            and property_device not in devices
        ):
            devices = (
                list(devices)
                + [property_device]
            )

        property_vrf = properties.get(
            "vrf"
        )

        if (
            property_vrf
            and property_vrf not in vrfs
        ):
            vrfs = (
                list(vrfs)
                + [property_vrf]
            )

        property_context = properties.get(
            "context"
        )

        if (
            property_context
            and property_context not in contexts
        ):
            contexts = (
                list(contexts)
                + [property_context]
            )

        if not vrfs:
            vrfs = [None]

        if not contexts:
            contexts = [None]

        for device in devices:

            self._add_device(
                result,
                device
            )

            device_type = (
                self._device_type(
                    device
                )
            )

            for vrf in vrfs:

                self._add_vrf(
                    result,
                    vrf
                )

                for context in contexts:

                    if context:

                        result[
                            "contexts"
                        ].add(context)

                    self._add_infrastructure_relation(
                        result,
                        device=device,
                        device_type=device_type,
                        interface=interface_name,
                        vrf=vrf,
                        context=context,
                        subnet=subnet,
                        protocol=protocol,
                        next_hop=next_hop,
                        endpoint=endpoint,
                        relation_source=(
                            relation_source
                        )
                    )


    def _add_infrastructure_relation(
        self,
        result,
        device,
        device_type=None,
        interface=None,
        vrf=None,
        context=None,
        subnet=None,
        protocol=None,
        next_hop=None,
        endpoint=None,
        relation_source=None
    ):

        if not device:
            return

        result[
            "infrastructure_relations"
        ].append({
            "device": device,
            "device_type": (
                device_type
                or self._device_type(
                    device
                )
            ),
            "interface": interface,
            "vrf": vrf,
            "context": context,
            "subnet": subnet,
            "protocol": protocol,
            "next_hop": next_hop,
            "endpoint": endpoint,
            "relation_source": (
                relation_source
            )
        })


    def _device_type(
        self,
        name
    ):

        if not name:
            return None

        if self.graph.find(
            "Router",
            name
        ):
            return "router"

        if self.graph.find(
            "Firewall",
            name
        ):
            return "firewall"

        return None


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