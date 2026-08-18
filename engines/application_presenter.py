from collections import defaultdict


class ApplicationPresenter:

    def render_text(self, model):

        application = model.get(
            "application",
            "Unknown"
        )

        communications = (
            model.get(
                "communication",
                {}
            ).get(
                "communications",
                []
            )
        )

        groups = defaultdict(list)

        for communication in communications:

            classifications = (
                communication.get(
                    "classification",
                    {}
                ).get(
                    "classifications",
                    []
                )
            )

            if classifications:

                for classification in classifications:

                    domain = (
                        classification.get(
                            "domain"
                        )
                        or "unclassified"
                    )

                    groups[domain].append({
                        "communication": communication,
                        "classification": classification
                    })

            else:

                groups[
                    "unclassified"
                ].append({
                    "communication": communication,
                    "classification": None
                })

        lines = []

        lines.append(
            f"APPLICATION: {application}"
        )

        lines.append(
            "=" * (
                len(application) + 13
            )
        )

        summary = model.get(
            "summary",
            {}
        )

        lines.append(
            f"Seed nodes          : "
            f"{summary.get('seed_nodes', 0)}"
        )

        lines.append(
            f"Core rules          : "
            f"{summary.get('core_rules', 0)}"
        )

        lines.append(
            f"Logical flows       : "
            f"{summary.get('logical_flows', 0)}"
        )

        lines.append(
            f"Communication pairs : "
            f"{summary.get('communication_pairs', 0)}"
        )

        lines.append("")

        domain_order = [
            "SCADA",
            "monitoring",
            "management",
            "printing"
        ]

        ordered_domains = []

        for domain in domain_order:

            if domain in groups:
                ordered_domains.append(
                    domain
                )

        for domain in sorted(
            groups.keys()
        ):

            if domain not in ordered_domains:
                ordered_domains.append(
                    domain
                )

        for domain in ordered_domains:

            lines.append(
                domain.upper()
            )

            lines.append(
                "-" * len(domain)
            )

            entries = groups[
                domain
            ]

            for entry in entries:

                communication = entry[
                    "communication"
                ]

                classification = entry[
                    "classification"
                ]

                source = (
                    communication.get(
                        "source",
                        {}
                    ).get(
                        "reference"
                    )
                )

                destination = (
                    communication.get(
                        "destination",
                        {}
                    ).get(
                        "reference"
                    )
                )

                context = communication.get(
                    "context"
                )

                services = []

                for service in communication.get(
                    "services",
                    []
                ):

                    protocol = service.get(
                        "protocol"
                    )

                    name = service.get(
                        "service"
                    )

                    if name:
                        services.append(
                            f"{protocol}/{name}"
                        )
                    else:
                        services.append(
                            str(protocol)
                        )

                lines.append(
                    f"{source}"
                )

                lines.append(
                    f"  -> {destination}"
                )

                lines.append(
                    f"     context: "
                    f"{context}"
                )

                lines.append(
                    f"     services: "
                    f"{', '.join(services)}"
                )

                if classification:

                    lines.append(
                        f"     classification: "
                        f"{classification.get('service')}"
                    )

                    lines.append(
                        f"     category: "
                        f"{classification.get('category')}"
                    )

                    lines.append(
                        f"     confidence: "
                        f"{classification.get('confidence')}"
                    )

                self._append_resolution_summary(
                    lines,
                    communication
                )

                lines.append("")

        return "\n".join(lines)


    def _append_resolution_summary(
        self,
        lines,
        communication
    ):

        source = communication.get(
            "source",
            {}
        )

        destination = communication.get(
            "destination",
            {}
        )

        lines.append(
            "     source inventory: "
            f"{len(source.get('hosts', []))} hosts, "
            f"{len(source.get('networks', []))} networks"
        )

        lines.append(
            "     destination inventory: "
            f"{len(destination.get('hosts', []))} hosts, "
            f"{len(destination.get('networks', []))} networks"
        )