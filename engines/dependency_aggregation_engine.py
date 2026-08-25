import hashlib
import re

from models.dependency import Dependency


class DependencyAggregationEngine:

    def __init__(
        self,
        classification_data=None
    ):

        self.classification_data = (
            classification_data
        )

    def aggregate(
        self,
        endpoints,
        classifications
    ):

        classification_by_key = {
            item.endpoint_key: item
            for item in classifications
        }

        #
        # Build reverse alias knowledge first.
        #
        alias_index = self._build_alias_index(
            endpoints
        )

        #
        # Canonical hosts that are actually resolved
        # in this analysed endpoint set.
        #
        resolved_host_keys = {
            f"host:{host}"
            for endpoint in endpoints
            for host in endpoint.resolved_hosts
        }

        dependencies = {}

        for endpoint in endpoints:

            classification = (
                classification_by_key.get(
                    endpoint.key
                )
            )

            service_mapping = (
                self._mapped_service(
                    endpoint
                )
            )

            dependency_key = (
                self._dependency_key(
                    endpoint=endpoint,
                    alias_index=alias_index,
                    service_mapping=service_mapping,
                    resolved_host_keys=resolved_host_keys
                )
            )

            dependency_name = (
                self._dependency_name(
                    endpoint=endpoint,
                    alias_index=alias_index,
                    service_mapping=service_mapping
                )
            )

            if dependency_key not in dependencies:

                dependencies[
                    dependency_key
                ] = Dependency(
                    key=dependency_key,
                    name=dependency_name
                )

            dependency = dependencies[
                dependency_key
            ]

            #
            # Prefer mapped service name when available.
            #
            if service_mapping:

                dependency.name = (
                    service_mapping.get(
                        "name",
                        dependency.name
                    )
                )

            self._merge_endpoint(
                dependency,
                endpoint
            )

            if classification:

                self._merge_classification(
                    dependency,
                    classification
                )

        results = list(
            dependencies.values()
        )

        results.sort(
            key=lambda item: (
                item.observed_rule_count,
                item.rule_count,
                item.endpoint_count
            ),
            reverse=True
        )

        return results

    def _build_alias_index(
        self,
        endpoints
    ):

        alias_index = {}

        for endpoint in endpoints:

            strong_key = None
            strong_name = None

            if (
                len(endpoint.resolved_hosts) == 1
                and not endpoint.resolved_networks
            ):

                strong_key = (
                    f"host:"
                    f"{endpoint.resolved_hosts[0]}"
                )

                strong_name = (
                    self._best_semantic_name(
                        endpoint
                    )
                )

            elif (
                len(endpoint.resolved_networks) == 1
                and not endpoint.resolved_hosts
            ):

                strong_key = (
                    f"network:"
                    f"{endpoint.resolved_networks[0]}"
                )

                strong_name = (
                    self._best_semantic_name(
                        endpoint
                    )
                )

            if not strong_key:
                continue

            candidates = []

            candidates.extend(
                endpoint.aliases
            )

            candidates.append(
                endpoint.display_name
            )

            for value in candidates:

                normalized = (
                    self._normalize(
                        value
                    )
                )

                if not normalized:
                    continue

                alias_index[
                    normalized
                ] = {
                    "key": strong_key,
                    "name": strong_name
                }

        return alias_index

    def _mapped_service(
        self,
        endpoint
    ):

        if not self.classification_data:
            return None

        #
        # Endpoint itself may be a mapped service.
        #
        mapping = (
            self.classification_data.find_service(
                endpoint.display_name
            )
        )

        if mapping:
            return mapping

        #
        # Or it may be a member of a mapped service/group.
        #
        for parent_group in endpoint.parent_groups:

            mapping = (
                self.classification_data.find_service(
                    parent_group
                )
            )

            if mapping:
                return mapping

        return None

    def _dependency_key(
        self,
        endpoint,
        alias_index,
        service_mapping,
        resolved_host_keys
    ):

        #
        # Highest semantic identity:
        # known logical service.
        #
        if service_mapping:

            service_name = (
                self._normalize(
                    service_mapping.get(
                        "name"
                    )
                )
            )

            return (
                f"service:"
                f"{service_name}"
            )

        #
        # Strong canonical host.
        #
        if (
            len(endpoint.resolved_hosts) == 1
            and not endpoint.resolved_networks
        ):

            return (
                f"host:"
                f"{endpoint.resolved_hosts[0]}"
            )

        #
        # Strong canonical network.
        #
        if (
            len(endpoint.resolved_networks) == 1
            and not endpoint.resolved_hosts
        ):

            return (
                f"network:"
                f"{endpoint.resolved_networks[0]}"
            )

        #
        # If this representation did not resolve,
        # see if its name/alias is already known as a
        # resolved canonical endpoint.
        #
        alias_match = (
            self._alias_match(
                endpoint,
                alias_index
            )
        )

        if alias_match:

            return alias_match[
                "key"
            ]

        #
        # Unresolved object may contain an IPv4 address
        # in its name.
        #
        # Only trust this if the same host already exists
        # as a resolved endpoint in the analysed dataset.
        #
        embedded_ip = (
            self._embedded_ip_match(
                endpoint,
                resolved_host_keys
            )
        )

        if embedded_ip:

            return embedded_ip[
                "key"
            ]

        #
        # Multi-member group.
        #
        members = self._member_keys(
            endpoint
        )

        if members:

            fingerprint = (
                self._member_fingerprint(
                    members
                )
            )

            return (
                f"group:"
                f"{fingerprint}"
            )

        if endpoint.endpoint_type == "any":

            return "any:any"

        #
        # Final semantic-name fallback.
        #
        return (
            f"name:"
            f"{self._normalize(endpoint.display_name)}"
        )

    def _dependency_name(
        self,
        endpoint,
        alias_index,
        service_mapping
    ):

        if service_mapping:

            return str(
                service_mapping.get(
                    "name"
                )
            )

        alias_match = (
            self._alias_match(
                endpoint,
                alias_index
            )
        )

        if (
            alias_match
            and alias_match.get(
                "name"
            )
        ):

            return alias_match[
                "name"
            ]

        return self._best_semantic_name(
            endpoint
        )

    def _best_semantic_name(
        self,
        endpoint
    ):

        #
        # Prefer names rather than literal IPs.
        #
        for alias in endpoint.aliases:

            if not self._looks_like_address(
                alias
            ):

                return str(
                    alias
                )

        return str(
            endpoint.display_name
        )

    def _alias_match(
        self,
        endpoint,
        alias_index
    ):

        candidates = []

        candidates.extend(
            endpoint.aliases
        )

        candidates.append(
            endpoint.display_name
        )

        for value in candidates:

            normalized = (
                self._normalize(
                    value
                )
            )

            if not normalized:
                continue

            match = alias_index.get(
                normalized
            )

            if match:

                return match

        return None

    def _member_keys(
        self,
        endpoint
    ):

        members = []

        for host in endpoint.resolved_hosts:

            members.append(
                f"host:{host}"
            )

        for network in endpoint.resolved_networks:

            members.append(
                f"network:{network}"
            )

        return sorted(
            set(
                members
            )
        )

    def _member_fingerprint(
        self,
        members
    ):

        canonical = "|".join(
            members
        )

        return hashlib.sha1(
            canonical.encode(
                "utf-8"
            )
        ).hexdigest()[:16]

    def _merge_endpoint(
        self,
        dependency,
        endpoint
    ):

        self._append_unique(
            dependency.endpoint_keys,
            endpoint.key
        )

        dependency.endpoint_count = len(
            dependency.endpoint_keys
        )

        for alias in endpoint.aliases:

            self._append_unique(
                dependency.aliases,
                alias
            )

        for service in endpoint.services:

            self._append_unique(
                dependency.services,
                service
            )

        for context in endpoint.contexts:

            self._append_unique(
                dependency.contexts,
                context
            )

        for host in endpoint.resolved_hosts:

            self._append_unique(
                dependency.resolved_hosts,
                host
            )

        for network in endpoint.resolved_networks:

            self._append_unique(
                dependency.resolved_networks,
                network
            )

        for group in endpoint.parent_groups:

            self._append_unique(
                dependency.parent_groups,
                group
            )

        dependency.member_count = (
            len(
                dependency.resolved_hosts
            )
            + len(
                dependency.resolved_networks
            )
        )

        dependency.rule_count += (
            endpoint.rule_count
        )

        dependency.observed_rule_count += (
            endpoint.observed_rule_count
        )

        dependency.total_hits += (
            endpoint.total_hits
        )

    def _merge_classification(
        self,
        dependency,
        classification
    ):

        rank = {
            "low": 1,
            "medium": 2,
            "high": 3
        }

        current_rank = rank.get(
            dependency.confidence,
            0
        )

        candidate_rank = rank.get(
            classification.confidence,
            0
        )

        if (
            classification.domain != "unknown"
            and candidate_rank >= current_rank
        ):

            dependency.domain = (
                classification.domain
            )

            dependency.confidence = (
                classification.confidence
            )

            dependency.reason = (
                classification.reason
            )

    def _looks_like_address(
        self,
        value
    ):

        text = str(
            value
        ).strip()

        if "/" in text:

            return True

        parts = text.split(
            "."
        )

        if len(parts) == 4:

            try:

                return all(
                    0 <= int(part) <= 255
                    for part in parts
                )

            except ValueError:
                pass

        return False

    def _normalize(
        self,
        value
    ):

        if value is None:
            return ""

        return (
            str(value)
            .strip()
            .lower()
        )

    def _extract_ipv4(
        self,
        value
    ):

        if not value:
            return []

        text = str(
            value
        )

        candidates = re.findall(
            r"(?<!\d)"
            r"(?:"
            r"(?:25[0-5]|2[0-4]\d|1?\d?\d)"
            r"\."
            r"){3}"
            r"(?:25[0-5]|2[0-4]\d|1?\d?\d)"
            r"(?!\d)",
            text
        )

        results = []

        for candidate in candidates:

            if candidate not in results:

                results.append(
                    candidate
                )

        return results

    def _embedded_ip_match(
        self,
        endpoint,
        resolved_host_keys
    ):

        candidates = []

        candidates.append(
            endpoint.display_name
        )

        candidates.extend(
            endpoint.aliases
        )

        for value in candidates:

            for address in self._extract_ipv4(
                value
            ):

                key = (
                    f"host:{address}"
                )

                #
                # Important:
                #
                # Embedded IP is only accepted when the
                # same canonical host already exists in
                # this analysed endpoint set.
                #
                if key in resolved_host_keys:

                    return {
                        "key": key,
                        "address": address
                    }

        return None

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