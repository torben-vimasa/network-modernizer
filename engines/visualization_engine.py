import ipaddress

from collections import defaultdict

from models.network_map_result import NetworkMapResult


class VisualizationEngine:

    def __init__(
        self,
        twin
    ):

        self.twin = twin
        self.graph = twin.graph

        self._network_map_cache = {}

        self._uses_source = defaultdict(
            list
        )

        self._uses_destination = defaultdict(
            list
        )

        self._group_members = defaultdict(
            list
        )

        self._network_cache = {}

        self._acl_rules = []

        self._build_indexes()

    #
    # =============================================================
    # PUBLIC API
    # =============================================================
    #
    def map_network(
        self,
        network
    ):

        target = ipaddress.ip_network(
            network,
            strict=False
        )

        cache_key = str(
            target
        )

        if cache_key in self._network_map_cache:

            return self._network_map_cache[
                cache_key
            ]

        network_objects = (
            self._find_network_objects(
                target
            )
        )

        object_groups = (
            self._find_object_groups(
                target
            )
        )

        routes = (
            self._find_routes(
                target
            )
        )

        outbound_rules = []
        inbound_rules = []

        for node in self._acl_rules:

            source_match = (
                self._rule_side_match(
                    node=node,
                    relationship_index=(
                        self._uses_source
                    ),
                    property_names=[
                        "source_value",
                        "source"
                    ],
                    target_network=target
                )
            )

            destination_match = (
                self._rule_side_match(
                    node=node,
                    relationship_index=(
                        self._uses_destination
                    ),
                    property_names=[
                        "destination_value",
                        "destination"
                    ],
                    target_network=target
                )
            )

            if source_match:

                item = self._acl_rule_data(
                    node
                )

                item[
                    "network_match"
                ] = source_match

                item[
                    "match_tier"
                ] = self._match_tier(
                    source_match
                )

                outbound_rules.append(
                    item
                )

            if destination_match:

                item = self._acl_rule_data(
                    node
                )

                item[
                    "network_match"
                ] = destination_match

                item[
                    "match_tier"
                ] = self._match_tier(
                    destination_match
                )

                inbound_rules.append(
                    item
                )

        outbound_rules = (
            self._deduplicate_rules(
                outbound_rules
            )
        )

        inbound_rules = (
            self._deduplicate_rules(
                inbound_rules
            )
        )

        contexts = []
        outbound_destinations = []
        inbound_sources = []
        services = []
        protocols = []

        for rule in (
            outbound_rules
            + inbound_rules
        ):

            self._append_unique(
                contexts,
                rule.get(
                    "context"
                )
            )

            self._append_unique(
                services,
                rule.get(
                    "service"
                )
            )

            self._append_unique(
                protocols,
                rule.get(
                    "protocol"
                )
            )

        for route in routes:

            self._append_unique(
                contexts,
                route.get(
                    "scope"
                )
            )

        for rule in outbound_rules:

            self._append_unique(
                outbound_destinations,
                rule.get(
                    "destination"
                )
            )

        for rule in inbound_rules:

            self._append_unique(
                inbound_sources,
                rule.get(
                    "source"
                )
            )

        result = NetworkMapResult(
            network=str(
                target
            ),

            network_objects=(
                network_objects
            ),

            object_groups=(
                object_groups
            ),

            routes=routes,

            outbound_rules=(
                outbound_rules
            ),

            inbound_rules=(
                inbound_rules
            ),

            contexts=contexts,

            outbound_destinations=(
                outbound_destinations
            ),

            inbound_sources=(
                inbound_sources
            ),

            services=services,

            protocols=protocols,

            route_count=len(
                routes
            ),

            network_object_count=len(
                network_objects
            ),

            object_group_count=len(
                object_groups
            ),

            outbound_rule_count=len(
                outbound_rules
            ),

            inbound_rule_count=len(
                inbound_rules
            ),

            confidence="high",

            reason=(
                "AS-IS network map derived from "
                "indexed Knowledge Graph routing, "
                "objects, object-groups and ACL policy."
            )
        )

        self._network_map_cache[
            cache_key
        ] = result

        return result

    #
    # =============================================================
    # INDEXING
    # =============================================================
    #
    def _build_indexes(
        self
    ):

        #
        # ACL rule list.
        #
        for node in self.graph.nodes.values():

            if node.type == "ACLRule":

                self._acl_rules.append(
                    node
                )

            elif node.type == "NetworkObject":

                self._network_cache[
                    node.id
                ] = self._node_network(
                    node
                )

        #
        # Relationship indexes.
        #
        for relationship in self.graph.relationships:

            if relationship.type == "USES_SOURCE":

                self._uses_source[
                    relationship.source
                ].append(
                    relationship.target
                )

            elif relationship.type == "USES_DESTINATION":

                self._uses_destination[
                    relationship.source
                ].append(
                    relationship.target
                )

            elif relationship.type == "HAS_MEMBER":

                self._group_members[
                    relationship.source
                ].append(
                    relationship.target
                )

    #
    # =============================================================
    # NETWORK OBJECTS
    # =============================================================
    #
    def _find_network_objects(
        self,
        target
    ):

        results = []

        for node_id, network in (
            self._network_cache.items()
        ):

            if network is None:
                continue

            match = (
                self._network_match(
                    network,
                    target
                )
            )

            if not match:
                continue

            node = self.graph.nodes.get(
                node_id
            )

            if not node:
                continue

            results.append({
                "id": node.id,
                "name": node.name,
                "value": (
                    node.properties.get(
                        "value"
                    )
                ),
                "network": str(
                    network
                ),
                "object_type": (
                    node.properties.get(
                        "type"
                    )
                ),
                "match_type": (
                    match.get(
                        "match_type"
                    )
                ),
                "match_tier": (
                    self._match_tier(
                        match
                    )
                )
            })

        return results

    #
    # =============================================================
    # OBJECT GROUPS
    # =============================================================
    #
    def _find_object_groups(
        self,
        target
    ):

        results = []

        for group_id, member_ids in (
            self._group_members.items()
        ):

            group = self.graph.nodes.get(
                group_id
            )

            if not group:
                continue

            matches = (
                self._group_target_matches(
                    group_id=group_id,
                    target_network=target,
                    visited=set()
                )
            )

            for match in matches:

                item = {
                    "group": group.name,
                    "group_id": group.id,
                    "member": (
                        match.get(
                            "member"
                        )
                    ),
                    "member_id": (
                        match.get(
                            "member_id"
                        )
                    ),
                    "member_network": (
                        match.get(
                            "network"
                        )
                    ),
                    "match_type": (
                        match.get(
                            "match_type"
                        )
                    ),
                    "match_tier": (
                        self._match_tier(
                            match
                        )
                    )
                }

                if item not in results:

                    results.append(
                        item
                    )

        return results

    #
    # =============================================================
    # ROUTES
    # =============================================================
    #
    def _find_routes(
        self,
        target
    ):

        results = []

        routes = []

        routes.extend(
            getattr(
                self.twin.route,
                "routes",
                []
            )
        )

        routes.extend(
            getattr(
                self.twin,
                "firewall_routes",
                []
            )
        )

        for route in routes:

            prefix = (
                self._route_value(
                    route,
                    "prefix"
                )
            )

            network = (
                self._parse_network_value(
                    prefix
                )
            )

            if network is None:
                continue

            match = (
                self._network_match(
                    network,
                    target
                )
            )

            if not match:
                continue

            item = {
                "device": (
                    self._route_value(
                        route,
                        "router"
                    )
                ),

                "scope": (
                    self._route_value(
                        route,
                        "vrf"
                    )
                ),

                "prefix": str(
                    network
                ),

                "protocol": (
                    self._route_value(
                        route,
                        "protocol"
                    )
                ),

                "next_hop": (
                    self._route_value(
                        route,
                        "next_hop"
                    )
                ),

                "interface": (
                    self._route_value(
                        route,
                        "interface"
                    )
                ),

                "egress_interface": (
                    self._route_value(
                        route,
                        "egress_interface"
                    )
                ),

                "match_type": (
                    match.get(
                        "match_type"
                    )
                ),

                "match_tier": (
                    self._match_tier(
                        match
                    )
                )
            }

            if item not in results:

                results.append(
                    item
                )

        return results

    #
    # =============================================================
    # ACL / POLICY MATCHING
    # =============================================================
    #
    def _rule_side_match(
        self,
        node,
        relationship_index,
        property_names,
        target_network
    ):

        best_match = None

        #
        # ---------------------------------------------------------
        # 1. ACL property itself.
        #
        # This tells us what is literally written in the ACL:
        #
        #   10.3.x.x          -> explicit
        #   10.0.0.0/8        -> covering
        #   any               -> any
        #   object/group name -> not parseable here; graph handles it
        # ---------------------------------------------------------
        #
        for property_name in property_names:

            value = node.properties.get(
                property_name
            )

            match = self._value_match(
                value,
                target_network
            )

            if not match:
                continue

            match = dict(
                match
            )

            match["source"] = "rule_property"
            match["value"] = value

            if match.get("match_type") in {
                "exact",
                "contained",
                "overlap"
            }:

                match["match_tier"] = "explicit"

            elif match.get("match_type") == "covering":

                match["match_tier"] = "covering"

            elif match.get("match_type") == "any":

                match["match_tier"] = "any"

            else:

                match["match_tier"] = "unknown"

            best_match = self._better_match(
                best_match,
                match
            )

        #
        # ---------------------------------------------------------
        # 2. Graph relationships.
        #
        # ACL references an object or object-group.
        # If the target network is reached through that graph
        # relationship, classify it as GROUP-derived unless the
        # referenced object itself represents a broad covering/any.
        # ---------------------------------------------------------
        #
        for target_id in relationship_index.get(
            node.id,
            []
        ):

            target_node = self.graph.nodes.get(
                target_id
            )

            if not target_node:
                continue

            match = self._node_matches_target(
                target_node,
                target_network,
                visited=set()
            )

            if not match:
                continue

            match = dict(
                match
            )

            match["source"] = "graph_relationship"
            match["node"] = target_node.name

            effective_type = (
                match.get("member_match_type")
                or match.get("match_type")
            )

            if effective_type == "any":

                match["match_tier"] = "any"

            elif effective_type == "covering":

                match["match_tier"] = "covering"

            else:

                #
                # The ACL did not contain the target network
                # literally. It reached it through an object or
                # object-group relationship.
                #
                match["match_tier"] = "group"

            best_match = self._better_match(
                best_match,
                match
            )

        return best_match

    def _node_matches_target(
        self,
        node,
        target_network,
        visited
    ):

        if node.id in visited:

            return None

        visited.add(
            node.id
        )

        #
        # Network object.
        #
        if node.type == "NetworkObject":

            network = (
                self._network_cache.get(
                    node.id
                )
            )

            if network is not None:

                match = (
                    self._network_match(
                        network,
                        target_network
                    )
                )

                if match:
                    return match

            return self._value_match(
                node.name,
                target_network
            )

        #
        # Object group.
        #
        if node.type == "ObjectGroup":

            best_match = None

            for member_id in self._group_members.get(
                node.id,
                []
            ):

                member = self.graph.nodes.get(
                    member_id
                )

                if not member:
                    continue

                match = (
                    self._node_matches_target(
                        member,
                        target_network,
                        visited
                    )
                )

                if not match:
                    continue

                wrapped = {
                    "match_type": (
                        "object_group"
                    ),
                    "member_match_type": (
                        match.get(
                            "match_type"
                        )
                    ),
                    "member": member.name,
                    "group": node.name,
                    "network": (
                        match.get(
                            "network"
                        )
                    )
                }

                best_match = (
                    self._better_match(
                        best_match,
                        wrapped
                    )
                )

            return best_match

        return None

    #
    # =============================================================
    # GROUP MATCHING
    # =============================================================
    #
    def _group_target_matches(
        self,
        group_id,
        target_network,
        visited
    ):

        if group_id in visited:

            return []

        visited.add(
            group_id
        )

        results = []

        for member_id in self._group_members.get(
            group_id,
            []
        ):

            member = self.graph.nodes.get(
                member_id
            )

            if not member:
                continue

            if member.type == "NetworkObject":

                network = (
                    self._network_cache.get(
                        member.id
                    )
                )

                if network is None:
                    continue

                match = (
                    self._network_match(
                        network,
                        target_network
                    )
                )

                if not match:
                    continue

                results.append({
                    "member": member.name,
                    "member_id": member.id,
                    "network": str(
                        network
                    ),
                    "match_type": (
                        match.get(
                            "match_type"
                        )
                    )
                })

            elif member.type == "ObjectGroup":

                nested = (
                    self._group_target_matches(
                        group_id=member.id,
                        target_network=target_network,
                        visited=visited
                    )
                )

                results.extend(
                    nested
                )

        return results

    #
    # =============================================================
    # MATCH SEMANTICS
    # =============================================================
    #
    def _value_match(
        self,
        value,
        target_network
    ):

        if value is None:

            return None

        text = str(
            value
        ).strip()

        lowered = text.lower()

        if lowered in {
            "any",
            "any4",
            "0.0.0.0/0",
            "0.0.0.0 0.0.0.0"
        }:

            return {
                "match_type": "any",
                "network": "0.0.0.0/0"
            }

        network = (
            self._parse_network_value(
                text
            )
        )

        if network is None:

            return None

        return self._network_match(
            network,
            target_network
        )

    def _network_match(
        self,
        candidate,
        target
    ):

        if (
            candidate.version == 4
            and candidate.prefixlen == 0
        ):

            return {
                "match_type": "any",
                "network": str(
                    candidate
                )
            }

        if candidate == target:

            return {
                "match_type": "exact",
                "network": str(
                    candidate
                )
            }

        if candidate.subnet_of(
            target
        ):

            return {
                "match_type": "contained",
                "network": str(
                    candidate
                )
            }

        if target.subnet_of(
            candidate
        ):

            return {
                "match_type": "covering",
                "network": str(
                    candidate
                )
            }

        if candidate.overlaps(
            target
        ):

            return {
                "match_type": "overlap",
                "network": str(
                    candidate
                )
            }

        return None

    def top_services(
        self,
        network,
        direction="both",
        top=10,
        active_only=False,
        action="permit"
    ):

        network_map = self.map_network(
            network
        )

        rules = []

        if direction in {
            "outbound",
            "both"
        }:

            for rule in network_map.outbound_rules:

                item = dict(
                    rule
                )

                item[
                    "_direction"
                ] = "outbound"

                rules.append(
                    item
                )

        if direction in {
            "inbound",
            "both"
        }:

            for rule in network_map.inbound_rules:

                item = dict(
                    rule
                )

                item[
                    "_direction"
                ] = "inbound"

                rules.append(
                    item
                )

        if action:

            rules = [
                rule
                for rule in rules
                if rule.get(
                    "action"
                ) == action
            ]

        if active_only:

            rules = [
                rule
                for rule in rules
                if (
                    isinstance(
                        rule.get(
                            "hitcnt"
                        ),
                        int
                    )
                    and rule.get(
                        "hitcnt"
                    ) > 0
                )
            ]

        grouped = {}

        for rule in rules:

            service = (
                rule.get(
                    "service"
                )
                or self._service_label(
                    rule
                )
            )

            protocol = (
                rule.get(
                    "protocol"
                )
                or "ip"
            )

            key = (
                protocol,
                service
            )

            if key not in grouped:

                grouped[
                    key
                ] = {
                    "service": service,
                    "protocol": protocol,
                    "direction": direction,
                    "rule_count": 0,
                    "active_rule_count": 0,
                    "total_hits": 0,
                    "endpoints": [],
                    "contexts": [],
                    "match_tiers": [],
                    "actions": []
                }

            summary = grouped[
                key
            ]

            summary[
                "rule_count"
            ] += 1

            hitcnt = rule.get(
                "hitcnt"
            )

            if (
                isinstance(
                    hitcnt,
                    int
                )
                and hitcnt > 0
            ):

                summary[
                    "active_rule_count"
                ] += 1

                summary[
                    "total_hits"
                ] += hitcnt

            endpoint = None

            if rule.get(
                "_direction"
            ) == "outbound":

                endpoint = rule.get(
                    "destination"
                )

            elif rule.get(
                "_direction"
            ) == "inbound":

                endpoint = rule.get(
                    "source"
                )

            self._append_unique(
                summary[
                    "endpoints"
                ],
                endpoint
            )

            self._append_unique(
                summary[
                    "contexts"
                ],
                rule.get(
                    "context"
                )
            )

            self._append_unique(
                summary[
                    "match_tiers"
                ],
                rule.get(
                    "match_tier"
                )
            )

            self._append_unique(
                summary[
                    "actions"
                ],
                rule.get(
                    "action"
                )
            )

        results = list(
            grouped.values()
        )

        #
        # Primary ranking:
        #
        # 1. total observed hits
        # 2. active rule count
        # 3. total rule count
        #
        results.sort(
            key=lambda item: (
                item[
                    "total_hits"
                ],
                item[
                    "active_rule_count"
                ],
                item[
                    "rule_count"
                ]
            ),
            reverse=True
        )

        if top is not None:

            results = results[
                :top
            ]

        return results

    def _service_label(
        self,
        rule
    ):

        service_type = rule.get(
            "service_type"
        )

        service_start = rule.get(
            "service_start"
        )

        service_end = rule.get(
            "service_end"
        )

        if (
            service_type == "range"
            and service_start
            and service_end
        ):

            return (
                f"{service_start}-"
                f"{service_end}"
            )

        if service_start:

            return str(
                service_start
            )

        protocol = rule.get(
            "protocol"
        )

        if protocol == "ip":

            return "any"

        return "unspecified"

    def map_service(
        self,
        network,
        service,
        direction="both",
        action="permit"
    ):

        network_map = self.map_network(
            network
        )

        service_normalized = str(
            service
        ).lower()

        rules = []

        if direction in {
            "outbound",
            "both"
        }:

            for rule in network_map.outbound_rules:

                if (
                    action
                    and rule.get("action") != action
                ):
                    continue

                if not self._service_matches(
                    rule,
                    service_normalized
                ):
                    continue

                item = dict(
                    rule
                )

                item["direction"] = "outbound"

                item["endpoint"] = (
                    rule.get(
                        "destination"
                    )
                )

                item["observed"] = (
                    isinstance(
                        rule.get("hitcnt"),
                        int
                    )
                    and rule.get("hitcnt") > 0
                )

                rules.append(
                    item
                )

        if direction in {
            "inbound",
            "both"
        }:

            for rule in network_map.inbound_rules:

                if (
                    action
                    and rule.get("action") != action
                ):
                    continue

                if not self._service_matches(
                    rule,
                    service_normalized
                ):
                    continue

                item = dict(
                    rule
                )

                item["direction"] = "inbound"

                item["endpoint"] = (
                    rule.get(
                        "source"
                    )
                )

                item["observed"] = (
                    isinstance(
                        rule.get("hitcnt"),
                        int
                    )
                    and rule.get("hitcnt") > 0
                )

                rules.append(
                    item
                )

        endpoints = []
        contexts = []
        match_tiers = []

        observed_rule_count = 0
        unknown_counter_count = 0

        for rule in rules:

            self._append_unique(
                endpoints,
                rule.get(
                    "endpoint"
                )
            )

            self._append_unique(
                contexts,
                rule.get(
                    "context"
                )
            )

            self._append_unique(
                match_tiers,
                rule.get(
                    "match_tier"
                )
            )

            hitcnt = rule.get(
                "hitcnt"
            )

            if (
                isinstance(
                    hitcnt,
                    int
                )
                and hitcnt > 0
            ):
                observed_rule_count += 1

            elif hitcnt is None:
                unknown_counter_count += 1

        return {
            "network": str(
                network
            ),

            "service": str(
                service
            ),

            "direction": direction,

            "action": action,

            "rule_count": len(
                rules
            ),

            "observed_rule_count": (
                observed_rule_count
            ),

            "unknown_counter_count": (
                unknown_counter_count
            ),

            "endpoint_count": len(
                endpoints
            ),

            "endpoints": endpoints,

            "contexts": contexts,

            "match_tiers": match_tiers,

            "rules": rules,

            "hitcount_note": (
                "ACL hit counters indicate observed use "
                "since the counter was last reset. "
                "Counter age is unknown and hit counts "
                "must not be interpreted as current "
                "traffic volume."
            )
        }


    def _service_matches(
        self,
        rule,
        service
    ):

        values = [
            rule.get(
                "service"
            ),
            rule.get(
                "service_start"
            ),
            rule.get(
                "service_end"
            )
        ]

        for value in values:

            if value is None:
                continue

            if str(
                value
            ).lower() == service:

                return True

        return False

    def render_service_mermaid(
        self,
        service_map,
        top=10
    ):

        network = service_map.get(
            "network"
        )

        service = service_map.get(
            "service"
        )

        rules = service_map.get(
            "rules",
            []
        )

        endpoint_data = {}

        for rule in rules:

            endpoint = rule.get(
                "endpoint"
            )

            if not endpoint:
                continue

            if endpoint not in endpoint_data:

                endpoint_data[
                    endpoint
                ] = {
                    "rules": 0,
                    "observed": 0,
                    "contexts": []
                }

            item = endpoint_data[
                endpoint
            ]

            item["rules"] += 1

            if rule.get(
                "observed"
            ):
                item["observed"] += 1

            self._append_unique(
                item["contexts"],
                rule.get(
                    "context"
                )
            )

        ranked = sorted(
            endpoint_data.items(),
            key=lambda item: (
                item[1]["observed"],
                item[1]["rules"]
            ),
            reverse=True
        )

        if top is not None:

            ranked = ranked[
                :top
            ]

        lines = [
            "flowchart LR",
            (
                f'    NET["{network}\\n'
                f'{service}"]'
            )
        ]

        for index, (
            endpoint,
            data
        ) in enumerate(
            ranked,
            start=1
        ):

            node_id = (
                f"EP{index}"
            )

            contexts = ", ".join(
                data[
                    "contexts"
                ]
            )

            label = (
                f"{endpoint}\\n"
                f"rules: {data['rules']}\\n"
                f"observed: {data['observed']}\\n"
                f"{contexts}"
            )

            lines.append(
                f'    {node_id}["{label}"]'
            )

            lines.append(
                f"    NET --> {node_id}"
            )

        return "\n".join(
            lines
        )

    def _match_tier(
        self,
        match
    ):

        if not match:
            return None

        #
        # If the matcher has already assigned semantic classification,
        # preserve it.
        #
        assigned_tier = match.get(
            "match_tier"
        )

        if assigned_tier in {
            "explicit",
            "group",
            "covering",
            "any"
        }:

            return assigned_tier

        match_type = match.get(
            "match_type"
        )

        member_match_type = match.get(
            "member_match_type"
        )

        effective = (
            member_match_type
            or match_type
        )

        if effective == "any":
            return "any"

        if effective == "covering":
            return "covering"

        if match_type == "object_group":
            return "group"

        if effective in {
            "exact",
            "contained",
            "overlap"
        }:
            return "explicit"

        return "unknown"

    def _better_match(
        self,
        current,
        candidate
    ):

        if current is None:
            return candidate

        rank = {
            "explicit": 1,
            "group": 2,
            "covering": 3,
            "any": 4,
            "unknown": 5
        }

        current_rank = rank.get(
            self._match_tier(
                current
            ),
            99
        )

        candidate_rank = rank.get(
            self._match_tier(
                candidate
            ),
            99
        )

        if candidate_rank < current_rank:
            return candidate

        return current
        
    def _node_network(
        self,
        node
    ):

        value = node.properties.get(
            "value"
        )

        network = (
            self._parse_network_value(
                value
            )
        )

        if network:
            return network

        return self._parse_network_value(
            node.name
        )

    def _parse_network_value(
        self,
        value
    ):

        if not value:
            return None

        value = str(
            value
        ).strip()

        lowered = value.lower()

        if lowered in {
            "any",
            "any4"
        }:

            return ipaddress.ip_network(
                "0.0.0.0/0"
            )

        try:

            if "/" in value:

                return ipaddress.ip_network(
                    value,
                    strict=False
                )

        except ValueError:
            pass

        try:

            address = ipaddress.ip_address(
                value
            )

            return ipaddress.ip_network(
                f"{address}/32",
                strict=False
            )

        except ValueError:
            pass

        parts = value.split()

        if len(parts) == 2:

            try:

                return ipaddress.ip_network(
                    (
                        parts[0],
                        parts[1]
                    ),
                    strict=False
                )

            except ValueError:
                pass

        normalized = (
            value
            .replace("_", " ")
            .replace("-", " ")
            .replace(":", " ")
        )

        for token in normalized.split():

            try:

                address = ipaddress.ip_address(
                    token
                )

                return ipaddress.ip_network(
                    f"{address}/32",
                    strict=False
                )

            except ValueError:
                continue

        return None

    def _acl_rule_data(
        self,
        node
    ):

        properties = node.properties

        return {
            "rule": node.name,
            "acl": properties.get(
                "acl"
            ),
            "sequence": properties.get(
                "sequence"
            ),
            "action": properties.get(
                "action"
            ),
            "protocol": properties.get(
                "protocol"
            ),
            "service": properties.get(
                "service"
            ),
            "service_type": properties.get(
                "service_type"
            ),
            "service_start": properties.get(
                "service_start"
            ),
            "service_end": properties.get(
                "service_end"
            ),
            "source": (
                properties.get(
                    "source_value"
                )
                or properties.get(
                    "source"
                )
            ),
            "destination": (
                properties.get(
                    "destination_value"
                )
                or properties.get(
                    "destination"
                )
            ),
            "source_type": properties.get(
                "source_type"
            ),
            "destination_type": properties.get(
                "destination_type"
            ),
            "context": properties.get(
                "context"
            ),
            "source_ifc": properties.get(
                "source_ifc"
            ),
            "destination_ifc": properties.get(
                "destination_ifc"
            ),
            "hitcnt": properties.get(
                "hitcnt"
            ),
            "raw": properties.get(
                "raw"
            )
        }

    def _route_value(
        self,
        route,
        name
    ):

        if isinstance(
            route,
            dict
        ):

            return route.get(
                name
            )

        return getattr(
            route,
            name,
            None
        )

    def _append_unique(
        self,
        values,
        value
    ):

        if (
            value
            and value not in values
        ):

            values.append(
                value
            )

    def _deduplicate_rules(
        self,
        rules
    ):

        results = []
        seen = set()

        for rule in rules:

            key = (
                rule.get(
                    "context"
                ),
                rule.get(
                    "acl"
                ),
                rule.get(
                    "sequence"
                ),
                rule.get(
                    "source"
                ),
                rule.get(
                    "destination"
                ),
                rule.get(
                    "protocol"
                ),
                rule.get(
                    "service"
                ),
                rule.get(
                    "match_tier"
                )
            )

            if key in seen:
                continue

            seen.add(
                key
            )

            results.append(
                rule
            )

        return results

    #
    # =============================================================
    # MERMAID
    # =============================================================
    #
    def render_mermaid(
        self,
        network_map
    ):

        lines = [
            "flowchart LR",
            f'    NET["{network_map.network}"]'
        ]

        for index, route in enumerate(
            network_map.routes,
            start=1
        ):

            device = (
                route.get(
                    "device"
                )
                or "unknown"
            )

            scope = (
                route.get(
                    "scope"
                )
                or "-"
            )

            prefix = (
                route.get(
                    "prefix"
                )
                or "-"
            )

            next_hop = (
                route.get(
                    "next_hop"
                )
                or "connected"
            )

            node_id = f"ROUTE{index}"

            label = (
                f"{device}\\n"
                f"{scope}\\n"
                f"{prefix}\\n"
                f"via {next_hop}"
            )

            lines.append(
                f'    {node_id}["{label}"]'
            )

            lines.append(
                f"    {node_id} --> NET"
            )

        for index, rule in enumerate(
            network_map.outbound_rules,
            start=1
        ):

            destination = (
                rule.get(
                    "destination"
                )
                or "unknown"
            )

            protocol = (
                rule.get(
                    "protocol"
                )
                or "ip"
            )

            service = (
                rule.get(
                    "service"
                )
                or "any"
            )

            context = (
                rule.get(
                    "context"
                )
                or "-"
            )

            tier = (
                rule.get(
                    "match_tier"
                )
                or "-"
            )

            node_id = f"OUT{index}"

            label = (
                f"{destination}\\n"
                f"{protocol}/{service}\\n"
                f"{context}\\n"
                f"{tier}"
            )

            lines.append(
                f'    {node_id}["{label}"]'
            )

            lines.append(
                f"    NET --> {node_id}"
            )

        for index, rule in enumerate(
            network_map.inbound_rules,
            start=1
        ):

            source = (
                rule.get(
                    "source"
                )
                or "unknown"
            )

            protocol = (
                rule.get(
                    "protocol"
                )
                or "ip"
            )

            service = (
                rule.get(
                    "service"
                )
                or "any"
            )

            context = (
                rule.get(
                    "context"
                )
                or "-"
            )

            tier = (
                rule.get(
                    "match_tier"
                )
                or "-"
            )

            node_id = f"IN{index}"

            label = (
                f"{source}\\n"
                f"{protocol}/{service}\\n"
                f"{context}\\n"
                f"{tier}"
            )

            lines.append(
                f'    {node_id}["{label}"]'
            )

            lines.append(
                f"    {node_id} --> NET"
            )

        return "\n".join(
            lines
        )