class ApplicationModelEngine:

    def __init__(
        self,
        application_view,
        communication_model
    ):
        self.application_view = application_view
        self.communication_model = communication_model


    def build(self, application_name):

        view = self.application_view.build(
            application_name
        )

        core_rules = self._select_core_rules(
            application_name,
            view
        )

        communication = (
            self.communication_model.build(
                core_rules
            )
        )

        return {
            "application": application_name,

            "discovery": {
                "known_application": (
                    view.get(
                        "known_application"
                    )
                ),
                "known_flows": (
                    view.get(
                        "known_flows",
                        []
                    )
                ),
                "seed_evidence": (
                    view.get(
                        "seed_evidence",
                        {}
                    )
                ),
                "expanded_evidence": (
                    view.get(
                        "expanded_evidence",
                        {}
                    )
                ),
                "relationships": (
                    view.get(
                        "relationships",
                        []
                    )
                )
            },

            "communication": communication,

            "summary": {
                "application": (
                    application_name
                ),

                "known_application": (
                    view["summary"].get(
                        "known_application"
                    )
                ),

                "seed_nodes": (
                    view["summary"].get(
                        "seed_nodes",
                        0
                    )
                ),

                "expanded_nodes": (
                    view["summary"].get(
                        "expanded_nodes",
                        0
                    )
                ),

                "core_rules": len(
                    core_rules
                ),

                "logical_flows": (
                    communication[
                        "summary"
                    ].get(
                        "logical_flows",
                        0
                    )
                ),

                "communication_pairs": (
                    communication[
                        "summary"
                    ].get(
                        "communication_pairs",
                        0
                    )
                ),

                "resolved_sources": (
                    communication[
                        "summary"
                    ].get(
                        "resolved_sources",
                        0
                    )
                ),

                "resolved_destinations": (
                    communication[
                        "summary"
                    ].get(
                        "resolved_destinations",
                        0
                    )
                )
            }
        }


    def _select_core_rules(
        self,
        application_name,
        view
    ):

        query = application_name.lower()

        seed_names = set()

        for items in view.get(
            "seed_evidence",
            {}
        ).values():

            for item in items:

                name = item.get(
                    "name"
                )

                if name:
                    seed_names.add(
                        name.lower()
                    )

        core = []

        for item in view.get(
            "expanded_evidence",
            {}
        ).get(
            "ACLRule",
            []
        ):

            properties = item.get(
                "properties",
                {}
            )

            values = [
                properties.get("source"),
                properties.get("destination"),
                properties.get("source_value"),
                properties.get("destination_value"),
                properties.get("service")
            ]

            text = " ".join(
                str(value or "")
                for value in values
            ).lower()

            direct_match = (
                query in text
            )

            seed_match = any(
                seed in text
                for seed in seed_names
                if len(seed) > 3
            )

            if (
                direct_match
                or seed_match
            ):
                core.append(
                    item
                )

        return core