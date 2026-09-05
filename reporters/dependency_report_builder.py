from models.dependency_report import (
    DependencyReport,
    DependencyReportEntry,
)


class DependencyReportBuilder:

    def __init__(self, digital_twin):
        self.digital_twin = digital_twin

    def build(
        self,
        network,
        direction="both",
        service=None,
        action="permit"
    ):

        endpoints = (
            self.digital_twin.aggregate_endpoints(
                network=network,
                direction=direction,
                service=service,
                action=action
            )
        )

        classifications = (
            self.digital_twin.endpoint_classification.classify(
                endpoints
            )
        )

        dependencies = (
            self.digital_twin.dependency_aggregation.aggregate(
                endpoints=endpoints,
                classifications=classifications
            )
        )

        hints = (
            self.digital_twin.dependency_hint_engine.enrich(
                dependencies=dependencies,
                source_network=network
            )
        )

        states = (
            self.digital_twin.dependency_state_engine.enrich(
                dependencies=dependencies,
                hints=hints
            )
        )

        hints_by_key = {
            hint.dependency_key: hint
            for hint in hints
        }

        states_by_key = {
            state.dependency_key: state
            for state in states
        }

        entries = []

        for dependency in dependencies:

            entries.append(
                DependencyReportEntry(
                    dependency=dependency,
                    hint=hints_by_key.get(
                        dependency.key
                    ),
                    state=states_by_key.get(
                        dependency.key
                    )
                )
            )

        report = DependencyReport(
            network=network,
            direction=direction,
            service=service,
            action=action,
            entries=entries
        )

        report.dependency_count = len(
            dependencies
        )

        report.inbound_count = sum(
            1
            for dependency in dependencies
            if "inbound" in dependency.directions
        )

        report.outbound_count = sum(
            1
            for dependency in dependencies
            if "outbound" in dependency.directions
        )

        report.high_confidence_count = sum(
            1
            for hint in hints
            if hint.confidence == "high"
        )

        report.medium_confidence_count = sum(
            1
            for hint in hints
            if hint.confidence == "medium"
        )

        report.low_confidence_count = sum(
            1
            for hint in hints
            if hint.confidence == "low"
        )

        report.full_coverage_count = sum(
            1
            for hint in hints
            if hint.coverage == "full"
        )

        report.sampled_coverage_count = sum(
            1
            for hint in hints
            if hint.coverage == "sampled"
        )

        report.not_applicable_coverage_count = sum(
            1
            for hint in hints
            if hint.coverage == "not-applicable"
        )

        report.target_count = sum(
            hint.target_count
            for hint in hints
        )

        report.attempted_target_count = sum(
            hint.attempted_target_count
            for hint in hints
        )

        report.evidence_target_count = sum(
            hint.evidence_target_count
            for hint in hints
        )

        for dependency in dependencies:
            evidence_class = dependency.evidence_class
            report.evidence_class_counts[evidence_class] = (
                report.evidence_class_counts.get(
                    evidence_class,
                    0
                )
                + 1
            )

            observation_state = dependency.observation_state
            report.observation_state_counts[observation_state] = (
                report.observation_state_counts.get(
                    observation_state,
                    0
                )
                + 1
            )

        return report
