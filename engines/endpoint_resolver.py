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

        for node in self.graph.nodes.values():

            if node.type not in [
                "NetworkObject",
                "IPAddress"
            ]:
                continue

            value = (
                node.properties.get("value")
                or node.properties.get("ip")
                or node.name
            )

            if str(value) != str(endpoint):
                continue

            matches.append({
                "type": node.type,
                "name": node.name,
                "id": node.id,
                "properties": node.properties
            })

        return matches


    def _find_best_subnet(self, ip):

        matches = []

        for node in self.graph.nodes.values():

            if node.type != "Subnet":
                continue

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

            if ip not in network:
                continue

            matches.append(
                (
                    network.prefixlen,
                    node
                )
            )

        if not matches:
            return None

        matches.sort(
            key=lambda item: item[0],
            reverse=True
        )

        return matches[0][1]


    def _find_best_routes(self, ip):

        matches = []

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

            if ip not in network:
                continue

            matches.append(
                (
                    network.prefixlen,
                    route
                )
            )

        if not matches:
            return []

        #
        # Longest prefix length wins.
        #
        best_prefixlen = max(
            prefixlen
            for prefixlen, route in matches
        )

        best_routes = []
        seen = set()

        for prefixlen, route in matches:

            if prefixlen != best_prefixlen:
                continue

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

        return results


    def _resolve_route_infrastructure(
        self,
        route
    ):

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
        # First resolve exact route owner / egress interface.
        #
        for node in self.graph.nodes.values():

            if node.type not in [
                "ASAInterface",
                "RouterInterface",
                "Interface"
            ]:
                continue

            node_device = (
                node.properties.get("device")
                or node.properties.get("router")
            )

            node_context = node.properties.get("context")
            node_vrf = node.properties.get("vrf")

            node_interface = (
                node.properties.get("nameif")
                or node.properties.get("interface")
                or node.properties.get("name")
            )

            #
            # Device/context match
            #
            owner_match = False

            if router_name and node_device == router_name:
                owner_match = True

            if router_name and node_context == router_name:
                owner_match = True

            #
            # VRF/context match can also identify ASA context.
            #
            if vrf and node_context == vrf:
                owner_match = True

            if not owner_match:
                continue
            #
            # If route has an explicit VRF, a router interface
            # must belong to that VRF.
            #
            if (
                vrf
                and node.type == "RouterInterface"
                and node_vrf != vrf
            ):
                continue


            #
            # If route has explicit egress interface,
            # require interface match.
            #
            if egress:

                if (
                    node_interface != egress
                    and node.name != egress
                    and not node.name.endswith(
                        f":{egress}"
                    )
                ):
                    continue


            #
            # Without an explicit egress interface we cannot
            # identify a specific ASA interface from owner alone.
            # The next-hop resolution below will determine it.
            #
            if (
                node.type == "ASAInterface"
                and not egress
            ):
                continue


            results.append(
                self._describe_interface(node)
            )

        #
        # Resolve next-hop into a connected subnet/interface.
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
                        item["role"] = "next_hop_subnet"

                        results.append(item)

        #
        # De-duplicate result dictionaries
        #
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

        return unique


    def _describe_interface(self, interface):

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
            "role": "direct",
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
        # Routing evidence.
        #
        exact_routes = []
        covering_routes = []

        for route in self.routes:

            route_prefix = route.get("prefix")

            if not route_prefix:
                continue

            try:
                route_network = ipaddress.ip_network(
                    route_prefix,
                    strict=False
                )
            except ValueError:
                continue

            #
            # Exact route to this network.
            #
            if route_network == network:
                exact_routes.append(route)
                continue

            #
            # Route summary covering this network.
            #
            if (
                route_network.version == network.version
                and network.subnet_of(route_network)
            ):
                covering_routes.append(route)

        #
        # De-duplicate route evidence.
        #
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