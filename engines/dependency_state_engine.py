from models.dependency_state import DependencyState


class DependencyStateEngine:

    def __init__(
        self,
        graph
    ):

        self.graph = graph

    def enrich(
        self,
        dependencies,
        hints
    ):

        hint_by_key = {
            hint.dependency_key: hint
            for hint in hints
        }

        results = []

        for dependency in dependencies:

            hint = hint_by_key.get(
                dependency.key
            )

            state = self._evaluate_dependency(
                dependency=dependency,
                hint=hint
            )

            results.append(
                state
            )

        return results

    def _evaluate_dependency(
        self,
        dependency,
        hint
    ):

        if hint is None:

            return DependencyState(
                dependency_key=dependency.key,
                dependency_name=dependency.name,
                operational_state="unknown",
                confidence="low",
                reason="No dependency hint evidence was available"
            )

        semantic_egress = [
            item
            for item in hint.evidence
            if item.get(
                "stage"
            ) == "semantic-egress"
        ]

        if not semantic_egress:

            return DependencyState(
                dependency_key=dependency.key,
                dependency_name=dependency.name,
                operational_state="unknown",
                confidence="low",
                reason=(
                    "No semantic egress evidence "
                    "was available"
                ),
                evidence=list(
                    hint.evidence
                )
            )

        matched_interfaces = []

        for item in semantic_egress:

            context = item.get(
                "context"
            )

            egress_interface = item.get(
                "egress_interface"
            )

            if (
                not context
                or not egress_interface
            ):

                continue

            interface_node = (
                self._find_interface(
                    context=context,
                    nameif=egress_interface
                )
            )

            if not interface_node:
                continue

            matched_interfaces.append({
                "context": context,
                "nameif": egress_interface,
                "interface": (
                    interface_node.properties.get(
                        "interface"
                    )
                ),
                "ip": (
                    interface_node.properties.get(
                        "ip"
                    )
                ),
                "shutdown": (
                    interface_node.properties.get(
                        "shutdown"
                    )
                )
            })

        if not matched_interfaces:

            return DependencyState(
                dependency_key=dependency.key,
                dependency_name=dependency.name,
                operational_state="unknown",
                confidence="low",
                reason=(
                    "Semantic egress was resolved, "
                    "but no matching ASA interface "
                    "state was found"
                ),
                evidence=list(
                    hint.evidence
                )
            )

        shutdown_interfaces = [
            item
            for item in matched_interfaces
            if item.get(
                "shutdown"
            ) is True
        ]

        active_interfaces = [
            item
            for item in matched_interfaces
            if item.get(
                "shutdown"
            ) is False
        ]

        #
        # All resolved egress interfaces are shutdown.
        #
        if (
            shutdown_interfaces
            and not active_interfaces
        ):

            names = sorted(
                {
                    (
                        f"{item.get('context')}:"
                        f"{item.get('nameif')}"
                    )
                    for item in shutdown_interfaces
                }
            )

            return DependencyState(
                dependency_key=dependency.key,
                dependency_name=dependency.name,
                operational_state="inactive-egress",
                confidence="high",
                reason=(
                    "Resolved egress interface is "
                    "administratively shutdown: "
                    + ", ".join(
                        names
                    )
                ),
                evidence=matched_interfaces
            )

        #
        # At least one resolved interface is active
        # and none are shutdown.
        #
        if (
            active_interfaces
            and not shutdown_interfaces
        ):

            names = sorted(
                {
                    (
                        f"{item.get('context')}:"
                        f"{item.get('nameif')}"
                    )
                    for item in active_interfaces
                }
            )

            return DependencyState(
                dependency_key=dependency.key,
                dependency_name=dependency.name,
                operational_state="active",
                confidence="high",
                reason=(
                    "Resolved egress interface is "
                    "administratively active: "
                    + ", ".join(
                        names
                    )
                ),
                evidence=matched_interfaces
            )

        #
        # Mixed interface state.
        #
        if (
            shutdown_interfaces
            and active_interfaces
        ):

            return DependencyState(
                dependency_key=dependency.key,
                dependency_name=dependency.name,
                operational_state="mixed",
                confidence="high",
                reason=(
                    "Dependency members resolve through "
                    "both active and shutdown interfaces"
                ),
                evidence=matched_interfaces
            )

        return DependencyState(
            dependency_key=dependency.key,
            dependency_name=dependency.name,
            operational_state="unknown",
            confidence="low",
            reason=(
                "Interface state could not be "
                "determined"
            ),
            evidence=matched_interfaces
        )

    def _find_interface(
        self,
        context,
        nameif
    ):

        for node in self.graph.nodes.values():

            if node.type != "ASAInterface":
                continue

            if (
                node.properties.get(
                    "context"
                ) != context
            ):
                continue

            if (
                node.properties.get(
                    "nameif"
                ) != nameif
            ):
                continue

            return node

        return None