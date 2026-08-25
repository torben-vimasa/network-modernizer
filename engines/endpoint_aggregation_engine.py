from models.logical_endpoint import LogicalEndpoint


class EndpointAggregationEngine:

    def __init__(
        self,
        object_resolver=None
    ):

        self.object_resolver = (
            object_resolver
        )

    def aggregate(
        self,
        network_map,
        direction="both",
        service=None,
        action="permit"
    ):

        rules = self._collect_rules(
            network_map=network_map,
            direction=direction
        )

        service_normalized = (
            str(service).lower()
            if service is not None
            else None
        )

        endpoints = {}

        for rule in rules:

            if (
                action
                and rule.get("action") != action
            ):
                continue

            if (
                service_normalized
                and not self._service_matches(
                    rule,
                    service_normalized
                )
            ):
                continue

            endpoint_value = (
                self._endpoint_value(
                    rule
                )
            )

            if not endpoint_value:
                continue

            endpoint_name = (
                self._endpoint_name(
                    rule
                )
            )

            endpoint_type = (
                self._endpoint_type(
                    rule
                )
            )

            context = rule.get(
                "context"
            )

            resolution = (
                self._resolve_endpoint(
                    endpoint_name=endpoint_name,
                    endpoint_value=endpoint_value,
                    endpoint_type=endpoint_type,
                    context=context
                )
            )

            logical_key = (
                self._logical_key(
                    endpoint_name=endpoint_name,
                    endpoint_value=endpoint_value,
                    endpoint_type=endpoint_type,
                    context=context,
                    resolution=resolution
                )
            )

            display_name = (
                self._display_name(
                    endpoint_name=endpoint_name,
                    endpoint_value=endpoint_value,
                    endpoint_type=endpoint_type
                )
            )

            if logical_key not in endpoints:

                endpoints[
                    logical_key
                ] = LogicalEndpoint(
                    key=logical_key,
                    display_name=display_name,
                    endpoint_type=(
                        self._canonical_type(
                            endpoint_type,
                            resolution
                        )
                    ),
                    direction=rule.get(
                        "_direction"
                    )
                )

            endpoint = endpoints[
                logical_key
            ]

            if self._is_better_display_name(
                current=endpoint.display_name,
                candidate=display_name,
                endpoint_type=endpoint_type
            ):

                endpoint.display_name = (
                    display_name
                )

            endpoint.rule_count += 1

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

                endpoint.observed_rule_count += 1
                endpoint.total_hits += hitcnt

            elif hitcnt is None:

                endpoint.unknown_counter_count += 1

            self._append_unique(
                endpoint.aliases,
                endpoint_name
            )

            self._append_unique(
                endpoint.aliases,
                endpoint_value
            )

            self._append_unique(
                endpoint.raw_values,
                endpoint_value
            )

            for host in resolution.get(
                "hosts",
                []
            ):

                self._append_unique(
                    endpoint.resolved_hosts,
                    host
                )

                self._append_unique(
                    endpoint.member_keys,
                    f"host:{host}"
                )

            for network in resolution.get(
                "networks",
                []
            ):

                self._append_unique(
                    endpoint.resolved_networks,
                    network
                )

                self._append_unique(
                    endpoint.member_keys,
                    f"network:{network}"
                )

            for object_name in resolution.get(
                "objects",
                []
            ):

                self._append_unique(
                    endpoint.resolved_objects,
                    object_name
                )

            for group_name in resolution.get(
                "groups",
                []
            ):

                self._append_unique(
                    endpoint.resolved_groups,
                    group_name
                )

            for unresolved in resolution.get(
                "unresolved",
                []
            ):

                self._append_unique(
                    endpoint.unresolved,
                    unresolved
                )

            endpoint.member_count = len(
                endpoint.member_keys
            )

            self._append_unique(
                endpoint.services,
                self._service_label(
                    rule
                )
            )

            self._append_unique(
                endpoint.contexts,
                context
            )

            self._append_unique(
                endpoint.match_tiers,
                rule.get(
                    "match_tier"
                )
            )

            endpoint.rules.append(
                dict(rule)
            )

            results = list(
                endpoints.values()
            )

            self._enrich_parent_groups(
                results
            )

            results.sort(
            key=lambda item: (
                item.observed_rule_count,
                item.rule_count,
                item.member_count
            ),
            reverse=True
        )

        return results

    def _collect_rules(
        self,
        network_map,
        direction
    ):

        rules = []

        if direction in {
            "outbound",
            "both"
        }:

            for rule in network_map.outbound_rules:

                item = dict(
                    rule
                )

                item["_direction"] = (
                    "outbound"
                )

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

                item["_direction"] = (
                    "inbound"
                )

                rules.append(
                    item
                )

        return rules

    def _endpoint_name(
        self,
        rule
    ):

        direction = rule.get(
            "_direction"
        )

        if direction == "outbound":
            return rule.get(
                "destination"
            )

        if direction == "inbound":
            return rule.get(
                "source"
            )

        return None

    def _endpoint_value(
        self,
        rule
    ):

        direction = rule.get(
            "_direction"
        )

        if direction == "outbound":

            return (
                rule.get(
                    "destination_value"
                )
                or rule.get(
                    "destination"
                )
            )

        if direction == "inbound":

            return (
                rule.get(
                    "source_value"
                )
                or rule.get(
                    "source"
                )
            )

        return None

    def _endpoint_type(
        self,
        rule
    ):

        direction = rule.get(
            "_direction"
        )

        if direction == "outbound":

            return (
                rule.get(
                    "destination_type"
                )
                or "unknown"
            )

        if direction == "inbound":

            return (
                rule.get(
                    "source_type"
                )
                or "unknown"
            )

        return "unknown"

    def _resolve_endpoint(
        self,
        endpoint_name,
        endpoint_value,
        endpoint_type,
        context
    ):

        empty = {
            "resolved": False,
            "hosts": [],
            "networks": [],
            "objects": [],
            "groups": [],
            "unresolved": []
        }

        if not self.object_resolver:
            return empty

        if (
            endpoint_type in {
                "object",
                "object-group"
            }
            and endpoint_name
        ):

            return self.object_resolver.resolve(
                endpoint_name,
                context=context
            )

        if endpoint_value:

            return self.object_resolver.resolve(
                endpoint_value,
                context=context
            )

        return empty

    def _logical_key(
        self,
        endpoint_name,
        endpoint_value,
        endpoint_type,
        context,
        resolution
    ):

        hosts = resolution.get(
            "hosts",
            []
        )

        networks = resolution.get(
            "networks",
            []
        )

        if (
            len(hosts) == 1
            and not networks
        ):

            return (
                f"host:{hosts[0]}"
            )

        if (
            len(networks) == 1
            and not hosts
        ):

            return (
                f"network:{networks[0]}"
            )

        if (
            endpoint_type == "object-group"
            and endpoint_name
        ):

            return (
                f"group:"
                f"{context}:"
                f"{endpoint_name}"
            )

        if (
            len(hosts)
            + len(networks)
            > 1
        ):

            return (
                f"multi:"
                f"{context}:"
                f"{endpoint_name or endpoint_value}"
            )

        if endpoint_type == "any":

            return "any:any"

        return (
            f"{endpoint_type}:"
            f"{endpoint_value}"
        )

    def _canonical_type(
        self,
        endpoint_type,
        resolution
    ):

        hosts = resolution.get(
            "hosts",
            []
        )

        networks = resolution.get(
            "networks",
            []
        )

        if (
            len(hosts) == 1
            and not networks
        ):

            return "host"

        if (
            len(networks) == 1
            and not hosts
        ):

            return "network"

        if (
            len(hosts)
            + len(networks)
            > 1
        ):

            return "group"

        return endpoint_type

    def _display_name(
        self,
        endpoint_name,
        endpoint_value,
        endpoint_type
    ):

        if (
            endpoint_type in {
                "object",
                "object-group"
            }
            and endpoint_name
        ):

            return str(
                endpoint_name
            )

        return str(
            endpoint_value
        )

    def _is_better_display_name(
        self,
        current,
        candidate,
        endpoint_type
    ):

        if not candidate:
            return False

        if not current:
            return True

        if endpoint_type in {
            "object",
            "object-group"
        }:

            return True

        return False

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

            if (
                str(value).lower()
                == service
            ):

                return True

        return False

    def _service_label(
        self,
        rule
    ):

        service = rule.get(
            "service"
        )

        if service:
            return str(
                service
            )

        service_start = rule.get(
            "service_start"
        )

        service_end = rule.get(
            "service_end"
        )

        if (
            service_start
            and service_end
            and service_start
            != service_end
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

        if protocol:
            return str(
                protocol
            )

        return "unspecified"

    def _append_unique(
        self,
        target,
        value
    ):

        if value is None:
            return

        if value not in target:

            target.append(
                value
            )

    def _enrich_parent_groups(
        self,
        endpoints
    ):

        endpoint_by_key = {
            endpoint.key: endpoint
            for endpoint in endpoints
        }

        for group in endpoints:

            if group.endpoint_type != "group":
                continue

            for member_key in group.member_keys:

                member = endpoint_by_key.get(
                    member_key
                )

                if not member:
                    continue

                self._append_unique(
                    member.parent_group_keys,
                    group.key
                )

                self._append_unique(
                    member.parent_groups,
                    group.display_name
                )