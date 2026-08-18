import ipaddress
from collections import defaultdict


class ApplicationViewEngine:

    def __init__(
        self,
        graph,
        endpoint_resolver,
        dependency_resolver
    ):
        self.graph = graph
        self.endpoint_resolver = endpoint_resolver
        self.dependency_resolver = dependency_resolver


    def build(self, application_name):

        query = application_name.lower()

        #
        # Known application, if it exists.
        #
        application = self.graph.find(
            "Application",
            application_name
        )

        known_application = None
        known_flows = []

        if application:

            known_application = {
                "name": application.name,
                "properties": application.properties
            }

            for relation, node in self.graph.neighbors(
                application.id
            ):

                if (
                    relation == "HAS_FLOW"
                    and node.type == "ApplicationFlow"
                ):
                    known_flows.append({
                        "name": node.name,
                        "properties": node.properties
                    })

        #
        # Discover graph evidence.
        #
        seed_evidence = defaultdict(list)
        expanded_evidence = defaultdict(list)

        endpoints = set()
        networks = set()

        seed_nodes = []

        #
        # Phase 1:
        # Find strong semantic seeds.
        #
        strong_seed_types = {
            "Application",
            "ApplicationFlow",
            "VRF",
            "ASAInterface",
            "RouterInterface",
            "ACL",
            "ObjectGroup",
            "NetworkObject"
        }

        for node in self.graph.nodes.values():

            if node.type not in strong_seed_types:
                continue

            if not self._matches_query(
                node,
                query
            ):
                continue

            seed_nodes.append(node)

            seed_evidence[node.type].append({
                "name": node.name,
                "properties": node.properties
            })

            self._extract_addresses(
                node,
                endpoints,
                networks
            )

        #
        # Phase 2:
        # Expand one graph hop from strong seeds.
        #
        expanded_nodes, relations = (
            self._expand_seeds(
                seed_nodes
            )
        )

        for node in expanded_nodes:

            expanded_evidence[node.type].append({
                "name": node.name,
                "properties": node.properties
            })

            self._extract_addresses(
                node,
                endpoints,
                networks
            )

        #
        # Known application flows must also contribute
        # endpoints even if their node text did not match
        # the search query.
        #
        for flow in known_flows:

            properties = flow["properties"]

            for key in [
                "source",
                "destination"
            ]:

                value = properties.get(key)

                self._classify_address(
                    value,
                    endpoints,
                    networks
                )

        #
        # Resolve discovered host endpoints.
        #
        endpoint_views = []

        for endpoint in sorted(
            endpoints,
            key=self._ip_sort_key
        ):

            endpoint_resolution = (
                self.endpoint_resolver.resolve(
                    endpoint
                )
            )

            dependency_resolution = (
                self.dependency_resolver.resolve_endpoint(
                    endpoint
                )
            )

            endpoint_views.append({
                "endpoint": endpoint,
                "resolution": endpoint_resolution,
                "dependencies": dependency_resolution
            })

        #
        # Compact summary.
        #
        summary = {
            "application": application_name,
            "known_application": (
                known_application is not None
            ),
            "known_flows": len(
                known_flows
            ),
            "seed_nodes": sum(
                len(items)
                for items in seed_evidence.values()
            ),
            "expanded_nodes": sum(
                len(items)
                for items in expanded_evidence.values()
            ),
            "relationships": len(relations),
            "endpoints": len(
                endpoints
            ),
            "networks": len(
                networks
            ),
            "resolved_endpoints": sum(
                1
                for item in endpoint_views
                if item["resolution"].get("found")
            ),
            "high_confidence_dependencies": sum(
                1
                for item in endpoint_views
                if item["dependencies"].get(
                    "confidence"
                ) == "high"
            )
        }

        return {
            "application": application_name,
            "known_application": known_application,
            "known_flows": known_flows,
            "seed_evidence": dict(seed_evidence),
            "expanded_evidence": dict(expanded_evidence),
            "relationships": relations,
            "endpoints": endpoint_views,
            "networks": sorted(
                networks,
                key=self._network_sort_key
            ),
            "summary": summary
        }

    def _expand_seeds(
        self,
        seeds
    ):

        expanded = {}
        relations = []

        allowed = {
            "BELONGS_TO_VRF",
            "PROTECTS",
            "USES_ACL",
            "IN_SUBNET",
            "CONNECTED_TO",
            "HAS_INTERFACE",
            "HAS_RULE"
        }

        for seed in seeds:

            for relation, neighbor in self.graph.neighbors(
                seed.id
            ):

                if relation not in allowed:
                    continue

                key = (
                    neighbor.type,
                    neighbor.name
                )

                expanded[key] = neighbor

                relations.append({
                    "source_type": seed.type,
                    "source": seed.name,
                    "relation": relation,
                    "target_type": neighbor.type,
                    "target": neighbor.name
                })

        return (
            list(expanded.values()),
            relations
        )

    def _matches_query(
        self,
        node,
        query
    ):

        #
        # Node name is strong evidence.
        #
        if query in str(
            node.name
        ).lower():
            return True

        #
        # Selected semantic properties.
        #
        properties = node.properties or {}

        searchable_keys = [
            "application",
            "description",
            "service",
            "business_service",
            "acl",
            "context",
            "name",
            "object",
            "source",
            "destination",
            "source_value",
            "destination_value",
            "raw"
        ]

        for key in searchable_keys:

            value = properties.get(key)

            if value is None:
                continue

            if query in str(
                value
            ).lower():
                return True

        return False


    def _extract_addresses(
        self,
        node,
        endpoints,
        networks
    ):

        properties = node.properties or {}

        for key in [
            "source",
            "destination",
            "source_value",
            "destination_value",
            "ip",
            "value"
        ]:

            value = properties.get(key)

            self._classify_address(
                value,
                endpoints,
                networks
            )


    def _classify_address(
        self,
        value,
        endpoints,
        networks
    ):

        if not value:
            return

        value = str(value).strip()

        #
        # Host IP.
        #
        try:

            ip = ipaddress.ip_address(
                value
            )

            endpoints.add(
                str(ip)
            )

            return

        except ValueError:
            pass

        #
        # Network.
        #
        try:

            network = ipaddress.ip_network(
                value,
                strict=False
            )

            networks.add(
                str(network)
            )

        except ValueError:
            pass


    def _ip_sort_key(
        self,
        value
    ):

        try:
            ip = ipaddress.ip_address(
                value
            )

            return (
                ip.version,
                int(ip)
            )

        except ValueError:

            return (
                99,
                value
            )


    def _network_sort_key(
        self,
        value
    ):

        try:

            network = ipaddress.ip_network(
                value,
                strict=False
            )

            return (
                network.version,
                int(network.network_address),
                network.prefixlen
            )

        except ValueError:

            return (
                99,
                value,
                0
            )