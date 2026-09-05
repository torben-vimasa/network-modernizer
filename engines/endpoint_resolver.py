import ipaddress


class EndpointResolver:

    def __init__(self, graph, routes=None):
        self.graph = graph
        self.routes = routes or []

        #
        # In-memory caches for this DigitalTwin instance.
        #
        self._resolve_cache = {}
        self._network_cache = {}
        self._subnet_infrastructure_cache = {}
        self._route_infrastructure_cache = {}

        #
        # Pre-built indexes.
        #
        self._exact_object_index = {}
        self._subnet_index = []
        self._route_index = []
        self._exact_route_index = {}
        self._interface_nodes = []

        self._build_indexes()


    def _build_indexes(self):

        #
        # Graph indexes.
        #
        for node in self.graph.nodes.values():

            if node.type in [
                "NetworkObject",
                "IPAddress"
            ]:

                value = (
                    node.properties.get("value")
                    or node.properties.get("ip")
                    or node.name
                )

                key = str(value)

                self._exact_object_index.setdefault(
                    key,
                    []
                ).append(node)

            if node.type == "Subnet":

                prefix = (
                    node.properties.get("prefix")
                    or node.name
                )

                try:
                    network = ipaddress.ip_network(
                        prefix,
                        strict=False
                    )
                except ValueError:
                    continue

                self._subnet_index.append(
                    (
                        network.prefixlen,
                        network,
                        node
                    )
                )

            if node.type in [
                "Interface",
                "ASAInterface",
                "RouterInterface"
            ]:
                self._interface_nodes.append(
                    node
                )

        #
        # Longest prefix match can now stop
        # at the first matching subnet.
        #
        self._subnet_index.sort(
            key=lambda item: item[0],
            reverse=True
        )

        #
        # Route indexes.
        #
        for route in self.routes:

            prefix = route.get("prefix")

            if not prefix:
                continue

            try:
                network = ipaddress.ip_network(
                    prefix,
                    strict=False
                )
            except ValueError:
                continue

            self._route_index.append(
                (
                    network.prefixlen,
                    network,
                    route
                )
            )

            normalized = str(network)

            self._exact_route_index.setdefault(
                normalized,
                []
            ).append(route)

        self._route_index.sort(
            key=lambda item: item[0],
            reverse=True
        )


    def resolve(self, endpoint):

        cache_key = str(endpoint)

        if cache_key in self._resolve_cache:
            return self._resolve_cache[cache_key]

        result = self._resolve_uncached(endpoint)

        self._resolve_cache[cache_key] = result

        return result


    def _resolve_uncached(self, endpoint):

        try:
            ip = ipaddress.ip_address(endpoint)
        except ValueError:
            return {
                "found": False,
                "endpoint": endpoint,
                "reason": "Endpoint is not a valid IP address",
                "confidence": "low"
            }

        exact_objects = self._find_exact_objects(endpoint)

        #
        # 1. Direct subnet ownership
        #
        subnet_node = self._find_best_subnet(ip)

        if subnet_node:

            infrastructure = self._resolve_subnet_infrastructure(
                subnet_node
            )

            return {
                "found": True,
                "endpoint": endpoint,
                "method": "direct_subnet",
                "exact_objects": exact_objects,
                "subnet": subnet_node.name,
                "route": None,
                "infrastructure": infrastructure,
                "confidence": (
                    "high"
                    if infrastructure
                    else "medium"
                ),
                "reason": (
                    f"Endpoint belongs directly to subnet "
                    f"{subnet_node.name}"
                )
            }

        #
        # 2. Routed ownership
        #
        routes = self._find_best_routes(ip)

        if routes:

            route_candidates = []

            for route in routes:

                route_candidates.append({
                    "route": route,
                    "infrastructure": (
                        self._resolve_route_infrastructure(
                            route
                        )
                    )
                })

            return {
                "found": True,
                "endpoint": endpoint,
                "method": "route_match",
                "exact_objects": exact_objects,
                "subnet": None,

                #
                # Backward-compatible primary route.
                #
                "route": routes[0],

                #
                # All equally specific routing evidence.
                #
                "route_candidates": route_candidates,

                "infrastructure": (
                    route_candidates[0]["infrastructure"]
                    if route_candidates
                    else []
                ),

                "confidence": "high",

                "reason": (
                    f"Endpoint matched "
                    f"{len(routes)} route candidate(s) "
                    f"for longest prefix "
                    f"{routes[0].get('prefix')}"
                )
            }

            return {
                "found": True,
                "endpoint": endpoint,
                "method": "route_match",
                "exact_objects": exact_objects,
                "subnet": None,
                "route": route,
                "infrastructure": route_infrastructure,
                "confidence": "high",
                "reason": (
                    f"Endpoint matched route "
                    f"{route.get('prefix')}"
                )
            }

        #
        # 3. Security/object evidence only
        #
        if exact_objects:

            return {
                "found": True,
                "endpoint": endpoint,
                "method": "object_only",
                "exact_objects": exact_objects,
                "subnet": None,
                "route": None,
                "infrastructure": [],
                "confidence": "medium",
                "reason": (
                    "Endpoint exists in graph as an object, "
                    "but no subnet or route ownership was resolved"
                )
            }

        return {
            "found": False,
            "endpoint": endpoint,
            "exact_objects": [],
            "subnet": None,
            "route": None,
            "infrastructure": [],
            "confidence": "low",
            "reason": "Endpoint was not resolved in graph or routing inventory"
        }


    def _find_exact_objects(self, endpoint):

        matches = []

        for node in self._exact_object_index.get(
            str(endpoint),
            []
        ):

            matches.append({
                "type": node.type,
                "name": node.name,
                "id": node.id,
                "properties": node.properties
            })

        return matches


    def _find_best_subnet(self, ip):

        for prefixlen, network, node in self._subnet_index:

            if ip in network:
                return node

        return None


    def _find_best_routes(self, ip):

        matches = []
        best_prefixlen = None

        for prefixlen, network, route in self._route_index:

            #
            # Because the index is sorted longest
            # prefix first, stop once we move below
            # the best matching prefix length.
            #
            if (
                best_prefixlen is not None
                and prefixlen < best_prefixlen
            ):
                break

            if ip not in network:
                continue

            if best_prefixlen is None:
                best_prefixlen = prefixlen

            matches.append(route)

        if not matches:
            return []

        best_routes = []
        seen = set()

        for route in matches:

            key = (
                route.get("router"),
                route.get("vrf"),
                route.get("prefix"),
                route.get("next_hop"),
                route.get("protocol"),
                route.get("egress_interface")
                or route.get("interface")
                or route.get("exit_interface")
            )

            if key in seen:
                continue

            seen.add(key)
            best_routes.append(route)

        return best_routes


    def _resolve_subnet_infrastructure(
        self,
        subnet_node
    ):

        cache_key = subnet_node.id

        if cache_key in self._subnet_infrastructure_cache:
            return self._subnet_infrastructure_cache[
                cache_key
            ]

        results = []
        seen = set()

        for relation, interface in self.graph.neighbors(
            subnet_node.id
        ):

            if relation != "IN_SUBNET":
                continue

            if interface.type not in [
                "Interface",
                "ASAInterface",
                "RouterInterface"
            ]:
                continue

            if interface.id in seen:
                continue

            seen.add(interface.id)

            results.append(
                self._describe_interface(interface)
            )

        self._subnet_infrastructure_cache[
            cache_key
        ] = results

        return results


    def _resolve_route_infrastructure(
        self,
        route
    ):

        cache_key = (
            route.get("router")
            or route.get("device"),
            route.get("vrf")
            or route.get("context"),
            route.get("prefix"),
            route.get("next_hop"),
            route.get("protocol"),
            route.get("egress_interface")
            or route.get("interface")
            or route.get("exit_interface")
        )

        if cache_key in self._route_infrastructure_cache:
            return self._route_infrastructure_cache[
                cache_key
            ]

        results = []

        router_name = (
            route.get("router")
            or route.get("device")
        )

        vrf = (
            route.get("vrf")
            or route.get("context")
        )

        egress = (
            route.get("egress_interface")
            or route.get("interface")
            or route.get("exit_interface")
        )

        next_hop = route.get("next_hop")

        #
        # Resolve exact route owner / egress interface only when
        # the route record explicitly identifies an egress interface.
        #
        # Route ownership alone is not sufficient evidence to select
        # one or more interfaces on the route-owning device.
        #
        if egress:

            for node in self._interface_nodes:

                node_device = (
                    node.properties.get("device")
                    or node.properties.get("router")
                )

                node_context = node.properties.get(
                    "context"
                )

                node_vrf = node.properties.get(
                    "vrf"
                )

                node_interface = (
                    node.properties.get("nameif")
                    or node.properties.get("interface")
                    or node.properties.get("name")
                )

                owner_match = False

                if (
                    router_name
                    and node_device == router_name
                ):
                    owner_match = True

                if (
                    router_name
                    and node_context == router_name
                ):
                    owner_match = True

                if (
                    vrf
                    and node_context == vrf
                ):
                    owner_match = True

                if not owner_match:
                    continue

                if (
                    vrf
                    and node.type == "RouterInterface"
                    and node_vrf != vrf
                ):
                    continue

                if (
                    node_interface != egress
                    and node.name != egress
                    and not node.name.endswith(
                        f":{egress}"
                    )
                ):
                    continue

                results.append(
                    self._describe_interface(
                        node,
                        role="route_egress"
                    )
                )

        #
        # Resolve next-hop into connected
        # subnet/interface using subnet index.
        #
        if next_hop:

            try:
                next_hop_ip = ipaddress.ip_address(
                    next_hop
                )
            except ValueError:
                next_hop_ip = None

            if next_hop_ip:

                next_hop_subnet = (
                    self._find_best_subnet(
                        next_hop_ip
                    )
                )

                if next_hop_subnet:

                    nh_infra = (
                        self._resolve_subnet_infrastructure(
                            next_hop_subnet
                        )
                    )

                    for item in nh_infra:

                        item = dict(item)
                        item["role"] = (
                            "next_hop_subnet"
                        )

                        results.append(item)

        unique = []
        seen = set()

        for item in results:

            key = (
                item.get("type"),
                item.get("name"),
                item.get("role")
            )

            if key in seen:
                continue

            seen.add(key)
            unique.append(item)

        self._route_infrastructure_cache[
            cache_key
        ] = unique

        return unique


    def _describe_interface(self, interface, role="direct"):

        devices = []
        contexts = []
        vrfs = []

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

        device = (
            interface.properties.get("device")
            or interface.properties.get("router")
        )

        if device:
            devices.append(device)

        for relation, neighbor in self.graph.neighbors(
            interface.id
        ):

            if (
                relation == "HAS_INTERFACE"
                and neighbor.type in [
                    "Firewall",
                    "Router",
                    "Context"
                ]
            ):

                if neighbor.type == "Context":

                    if neighbor.name not in contexts:
                        contexts.append(
                            neighbor.name
                        )

                else:

                    if neighbor.name not in devices:
                        devices.append(
                            neighbor.name
                        )

            elif (
                relation == "BELONGS_TO_VRF"
                and neighbor.type == "VRF"
            ):

                if neighbor.name not in vrfs:
                    vrfs.append(
                        neighbor.name
                    )

        return {
            "type": interface.type,
            "name": interface.name,
            "interface": (
                interface.properties.get("nameif")
                or interface.properties.get("interface")
                or interface.properties.get("name")
                or interface.name
            ),
            "ip": interface.properties.get("ip"),
            "devices": sorted(set(devices)),
            "contexts": sorted(set(contexts)),
            "vrfs": sorted(set(vrfs)),
            "role": role,
            "properties": interface.properties
        }

    def resolve_network(self, prefix):

        cache_key = str(prefix)

        if cache_key in self._network_cache:
            return self._network_cache[cache_key]

        result = self._resolve_network_uncached(prefix)

        self._network_cache[cache_key] = result

        return result


    def _resolve_network_uncached(self, prefix):

        try:
            network = ipaddress.ip_network(
                prefix,
                strict=False
            )
        except ValueError:
            return {
                "found": False,
                "network": prefix,
                "reason": "Invalid network prefix",
                "confidence": "low"
            }

        normalized = str(network)

        #
        # Exact subnet inventory evidence.
        #
        subnet_node = self.graph.find(
            "Subnet",
            normalized
        )

        infrastructure = []

        if subnet_node:
            infrastructure = (
                self._resolve_subnet_infrastructure(
                    subnet_node
                )
            )

        #
        # Routing evidence from pre-parsed index.
        #
        exact_routes = list(
            self._exact_route_index.get(
                normalized,
                []
            )
        )

        covering_routes = []

        for prefixlen, route_network, route in (
            self._route_index
        ):

            if route_network == network:
                continue

            if (
                route_network.version
                == network.version
                and network.subnet_of(
                    route_network
                )
            ):
                covering_routes.append(
                    route
                )

        exact_routes = self._deduplicate_routes(
            exact_routes
        )

        covering_routes = self._deduplicate_routes(
            covering_routes
        )

        found = bool(
            subnet_node
            or exact_routes
            or covering_routes
        )

        if subnet_node and infrastructure:
            confidence = "high"
            reason = (
                f"Network {normalized} exists as subnet "
                f"with infrastructure relationships"
            )

        elif exact_routes:
            confidence = "high"
            reason = (
                f"Network {normalized} has exact routing evidence"
            )

        elif covering_routes:
            confidence = "medium"
            reason = (
                f"Network {normalized} is covered by routing summaries"
            )

        else:
            confidence = "low"
            reason = (
                f"Network {normalized} was not resolved"
            )

        return {
            "found": found,
            "network": normalized,
            "subnet": (
                subnet_node.name
                if subnet_node
                else None
            ),
            "infrastructure": infrastructure,
            "exact_routes": exact_routes,
            "covering_routes": covering_routes,
            "confidence": confidence,
            "reason": reason
        }


    def _deduplicate_routes(self, routes):

        result = []
        seen = set()

        for route in routes:

            key = (
                route.get("router"),
                route.get("vrf"),
                route.get("prefix"),
                route.get("next_hop"),
                route.get("protocol"),
                route.get("egress_interface")
                or route.get("interface")
                or route.get("exit_interface")
            )

            if key in seen:
                continue

            seen.add(key)
            result.append(route)

        return result