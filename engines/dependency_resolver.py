class DependencyResolver:

    def __init__(self, graph, endpoint_resolver):
        self.graph = graph
        self.endpoint_resolver = endpoint_resolver


    def resolve_endpoint(self, endpoint):

        endpoint_result = self.endpoint_resolver.resolve(
            endpoint
        )

                #
        # Direct subnet dependency.
        #
        if (
            endpoint_result.get("method")
            == "direct_subnet"
        ):

            infrastructure = endpoint_result.get(
                "infrastructure",
                []
            )

            dependencies = []

            for item in infrastructure:

                dependencies.append({
                    "route_owner": (
                        (item.get("devices") or [None])[0]
                    ),
                    "vrf": (
                        (item.get("vrfs") or [None])[0]
                    ),
                    "prefix": endpoint_result.get(
                        "subnet"
                    ),
                    "protocol": "connected",
                    "next_hop": None,
                    "next_hop_type": "direct_subnet",
                    "redundancy": [],
                    "interfaces": [
                        item
                    ],
                    "routers": [
                        device
                        for device in item.get(
                            "devices",
                            []
                        )
                        if self.graph.find(
                            "Router",
                            device
                        )
                    ],
                    "contexts": item.get(
                        "contexts",
                        []
                    ),
                    "confidence": (
                        endpoint_result.get(
                            "confidence",
                            "high"
                        )
                    )
                })

            return {
                "found": True,
                "endpoint": endpoint,
                "endpoint_resolution": endpoint_result,
                "dependencies": dependencies,
                "confidence": endpoint_result.get(
                    "confidence",
                    "high"
                ),
                "reason": (
                    f"Endpoint belongs directly to "
                    f"{endpoint_result.get('subnet')}"
                )
            }

        if not endpoint_result.get("found"):

            return {
                "found": False,
                "endpoint": endpoint,
                "reason": endpoint_result.get("reason"),
                "confidence": "low"
            }

        route_candidates = endpoint_result.get(
            "route_candidates",
            []
        )

        dependencies = []

        for candidate in route_candidates:

            route = candidate.get("route", {})

            dependency = self._build_route_dependency(
                route
            )

            if dependency:
                dependencies.append(
                    dependency
                )

        return {
            "found": True,
            "endpoint": endpoint,
            "endpoint_resolution": endpoint_result,
            "dependencies": dependencies,
            "confidence": self._calculate_confidence(
                dependencies
            ),
            "reason": (
                f"Resolved {len(dependencies)} "
                f"dependency path(s)"
            )
        }


    def _build_route_dependency(self, route):

        router = (
            route.get("router")
            or route.get("device")
        )

        vrf = (
            route.get("vrf")
            or route.get("context")
        )

        prefix = route.get("prefix")
        next_hop = route.get("next_hop")
        protocol = route.get("protocol")

        dependency = {
            "route_owner": router,
            "vrf": vrf,
            "prefix": prefix,
            "protocol": protocol,
            "next_hop": next_hop,
            "next_hop_type": None,
            "redundancy": [],
            "interfaces": [],
            "routers": [],
            "contexts": [],
            "confidence": "medium"
        }

        #
        # Find interfaces directly related to route owner / VRF
        #
        for node in self.graph.nodes.values():

            if node.type not in [
                "RouterInterface",
                "ASAInterface"
            ]:
                continue

            node_router = node.properties.get(
                "router"
            )

            node_context = node.properties.get(
                "context"
            )

            node_vrf = node.properties.get(
                "vrf"
            )

            owner_match = False

            if router and node_router == router:
                owner_match = True

            if router and node_context == router:
                owner_match = True

            if not owner_match:
                continue

            #
            # Router interfaces must belong to the route VRF.
            #
            if (
                node.type == "RouterInterface"
                and vrf
                and node_vrf != vrf
            ):
                continue

            #
            # Do not add every ASA interface merely because it
            # belongs to the route-owning firewall context.
            #
            # ASA route egress is resolved through next-hop
            # semantics below unless an explicit interface exists.
            #
            if node.type == "ASAInterface":
                continue

            dependency["interfaces"].append(
                self._describe_interface(node)
            )

        #
        # Resolve next-hop semantics
        #
        if next_hop:

            redundancy = self._find_redundancy_group(
                next_hop
            )

            if redundancy:

                dependency["next_hop_type"] = (
                    "redundancy_virtual_ip"
                )

                dependency["redundancy"] = redundancy

                for member in redundancy:

                    router_name = member.get(
                        "router"
                    )

                    if (
                        router_name
                        and router_name
                        not in dependency["routers"]
                    ):
                        dependency["routers"].append(
                            router_name
                        )

                dependency["confidence"] = "high"

            else:

                dependency["next_hop_type"] = (
                    "direct_or_routed_next_hop"
                )

        #
        # Context / VRF enrichment
        #
        for interface in dependency["interfaces"]:

            for context in interface.get(
                "contexts",
                []
            ):

                if context not in dependency["contexts"]:
                    dependency["contexts"].append(
                        context
                    )

            for item_vrf in interface.get(
                "vrfs",
                []
            ):

                if (
                    item_vrf
                    and not dependency.get("vrf")
                ):
                    dependency["vrf"] = item_vrf

        return dependency


    def _find_redundancy_group(
        self,
        virtual_ip
    ):

        members = []

        for node in self.graph.find_by_type(
            "RouterInterface"
        ):

            if (
                node.properties.get(
                    "hsrp_virtual_ip"
                )
                != virtual_ip
            ):
                continue

            members.append({
                "type": "HSRP",
                "virtual_ip": virtual_ip,
                "router": node.properties.get(
                    "router"
                ),
                "interface": node.properties.get(
                    "interface"
                ),
                "ip": node.properties.get(
                    "ip"
                ),
                "priority": node.properties.get(
                    "hsrp_priority"
                ),
                "state": node.properties.get(
                    "hsrp_state"
                ),
                "vrf": node.properties.get(
                    "vrf"
                ),
                "node": node.name
            })

        return members


    def _describe_interface(
        self,
        interface
    ):

        devices = []
        contexts = []
        vrfs = []

        device = (
            interface.properties.get("device")
            or interface.properties.get("router")
        )

        if device:
            devices.append(device)

        context = interface.properties.get(
            "context"
        )

        if context:
            contexts.append(context)

        vrf = interface.properties.get(
            "vrf"
        )

        if vrf:
            vrfs.append(vrf)

        for relation, neighbor in self.graph.neighbors(
            interface.id
        ):

            if (
                relation == "BELONGS_TO_VRF"
                and neighbor.type == "VRF"
            ):

                if neighbor.name not in vrfs:
                    vrfs.append(
                        neighbor.name
                    )

            elif (
                relation == "HAS_INTERFACE"
                and neighbor.type == "Context"
            ):

                if neighbor.name not in contexts:
                    contexts.append(
                        neighbor.name
                    )

        return {
            "type": interface.type,
            "name": interface.name,
            "interface": (
                interface.properties.get("nameif")
                or interface.properties.get("interface")
                or interface.name
            ),
            "ip": interface.properties.get("ip"),
            "devices": sorted(set(devices)),
            "contexts": sorted(set(contexts)),
            "vrfs": sorted(set(vrfs))
        }


    def _calculate_confidence(
        self,
        dependencies
    ):

        if not dependencies:
            return "low"

        if any(
            d.get("confidence") == "high"
            for d in dependencies
        ):
            return "high"

        return "medium"