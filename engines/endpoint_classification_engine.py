from models.endpoint_classification import (
    EndpointClassification
)


class EndpointClassificationEngine:

    def __init__(
        self,
        classification_data=None
    ):

        self.classification_data = (
            classification_data
        )

    def classify(
        self,
        endpoints
    ):

        results = []

        for endpoint in endpoints:

            classification = (
                self._classify_endpoint(
                    endpoint
                )
            )

            results.append(
                EndpointClassification(
                    endpoint_key=endpoint.key,
                    display_name=endpoint.display_name,
                    domain=classification[
                        "domain"
                    ],
                    confidence=classification[
                        "confidence"
                    ],
                    reason=classification[
                        "reason"
                    ],
                    direction=endpoint.direction,
                    endpoint_type=endpoint.endpoint_type,
                    contexts=list(
                        endpoint.contexts
                    ),
                    services=list(
                        endpoint.services
                    ),
                    aliases=list(
                        endpoint.aliases
                    ),
                    parent_groups=list(
                        endpoint.parent_groups
                    ),
                    member_count=endpoint.member_count,
                    rule_count=endpoint.rule_count,
                    observed_rule_count=(
                        endpoint.observed_rule_count
                    ),
                    total_hits=endpoint.total_hits
                )
            )

        return results

    def _classify_endpoint(
        self,
        endpoint
    ):

        #
        # 1. Explicit ownership mapping.
        #

        ownership = (
            self._find_ownership(
                endpoint
            )
        )

        if ownership:

            return {
                "domain": ownership.get(
                    "domain",
                    "unknown"
                ),
                "confidence": ownership.get(
                    "confidence",
                    "high"
                ),
                "reason": (
                    "Explicit ownership mapping "
                    f"for {ownership.get('name')}"
                )
            }

        #
        # 2. Explicit service mapping for
        #    endpoint/group name.
        #

        service = (
            self._find_service(
                endpoint.display_name
            )
        )

        if service:

            return {
                "domain": service.get(
                    "domain",
                    "unknown"
                ),
                "confidence": service.get(
                    "confidence",
                    "high"
                ),
                "reason": (
                    "Explicit service mapping "
                    f"for {service.get('name')}"
                )
            }

        #
        # 3. Membership of known logical service.
        #

        for parent_group in (
            endpoint.parent_groups
        ):

            service = (
                self._find_service(
                    parent_group
                )
            )

            if service:

                return {
                    "domain": service.get(
                        "domain",
                        "unknown"
                    ),
                    "confidence": service.get(
                        "confidence",
                        "high"
                    ),
                    "reason": (
                        "Member of mapped service "
                        f"{service.get('name')}"
                    )
                }

        #
        # 4. Explicit network ownership/domain.
        #

        network = (
            self._find_network(
                endpoint
            )
        )

        if network:

            return {
                "domain": network.get(
                    "domain",
                    "unknown"
                ),
                "confidence": network.get(
                    "confidence",
                    "high"
                ),
                "reason": (
                    "Matched network mapping "
                    f"{network.get('network')}"
                )
            }

        #
        # 5. ANY remains unknown.
        #

        if (
            endpoint.endpoint_type == "any"
            or endpoint.key == "any:any"
        ):

            return {
                "domain": "unknown",
                "confidence": "low",
                "reason": (
                    "ACL destination is any; "
                    "destination domain cannot be inferred"
                )
            }

        #
        # 6. No evidence.
        #

        return {
            "domain": "unknown",
            "confidence": "low",
            "reason": (
                "No explicit ownership, service "
                "or network evidence"
            )
        }

    def _find_service(
        self,
        name
    ):

        if not self.classification_data:
            return None

        return (
            self.classification_data.find_service(
                name
            )
        )

    def _find_ownership(
        self,
        endpoint
    ):

        if not self.classification_data:
            return None

        addresses = []

        addresses.extend(
            endpoint.resolved_hosts
        )

        addresses.extend(
            endpoint.resolved_networks
        )

        return (
            self.classification_data.find_ownership(
                name=endpoint.display_name,
                addresses=addresses
            )
        )

    def _find_network(
        self,
        endpoint
    ):

        if not self.classification_data:
            return None

        addresses = []

        addresses.extend(
            endpoint.resolved_hosts
        )

        addresses.extend(
            endpoint.resolved_networks
        )

        return (
            self.classification_data.find_network(
                addresses
            )
        )