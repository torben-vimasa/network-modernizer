class DependencyReportRenderer:

    def _render_routing_path(self, evidence):

        lines = []

        if not evidence:
            return lines

        path_stages = {
            "source-resolution",
            "destination-resolution",
            "router-route",
            "router-egress",
            "firewall-route",
            "firewall-next-hop-route",
            "firewall-next-hop-resolution",
            "hsrp-next-hop-resolution",
            "semantic-egress",
            "inventory-boundary",
            "routing-loop",
            "traversal-limit",
        }

        path_evidence = [
            item
            for item in evidence
            if item.get("stage") in path_stages
        ]

        if not path_evidence:
            return lines

        lines.append("")
        lines.append("ROUTING PATH")

        for item in path_evidence:

            stage = item.get("stage")

            if stage == "source-resolution":

                resolution = item.get(
                    "source_resolution",
                    "unknown"
                )

                source = item.get("source")
                device = item.get("device")
                interface = item.get("interface")
                next_hop = item.get("next_hop")
                route_prefixes = item.get("route_prefixes")

                detail = []

                if source:
                    detail.append(
                        f"source {source}"
                    )

                detail.append(
                    f"resolution {resolution}"
                )

                if device:
                    detail.append(
                        f"device {device}"
                    )

                if interface:
                    detail.append(
                        f"interface {interface}"
                    )

                if next_hop:
                    detail.append(
                        f"next-hop {next_hop}"
                    )

                if route_prefixes:
                    detail.append(
                        "routes "
                        + ", ".join(route_prefixes)
                    )

                lines.append(
                    "  Source: "
                    + " | ".join(detail)
                )

            elif stage == "destination-resolution":

                destination = item.get("destination")
                reason = item.get("reason")

                detail = []

                if destination:
                    detail.append(
                        f"destination {destination}"
                    )

                if reason:
                    detail.append(reason)

                lines.append(
                    "  Destination: "
                    + (
                        " | ".join(detail)
                        if detail
                        else "unresolved"
                    )
                )

            elif stage == "firewall-route":

                context = item.get("context") or "unknown"
                prefix = item.get("prefix")
                protocol = item.get("protocol")
                next_hop = item.get("next_hop")
                egress = (
                    item.get("egress_interface")
                    or item.get("interface")
                )

                detail = []

                if prefix:
                    detail.append(
                        f"route {prefix}"
                    )

                if protocol:
                    detail.append(
                        f"protocol {protocol}"
                    )

                if next_hop:
                    detail.append(
                        f"next-hop {next_hop}"
                    )

                if egress:
                    detail.append(
                        f"egress {egress}"
                    )

                lines.append(
                    f"  Firewall {context}: "
                    + " | ".join(detail)
                )

            elif stage == "firewall-next-hop-resolution":

                device = (
                    item.get("device")
                    or item.get("context")
                    or item.get("node_name")
                    or "unknown"
                )

                interface = (
                    item.get("nameif")
                    or item.get("interface")
                )

                ip = item.get("ip")

                detail = []

                if interface:
                    detail.append(
                        f"interface {interface}"
                    )

                if ip:
                    detail.append(
                        f"ip {ip}"
                    )

                lines.append(
                    f"  Next hop device {device}: "
                    + (
                        " | ".join(detail)
                        if detail
                        else "resolved"
                    )
                )

            elif stage == "firewall-next-hop-route":

                context = item.get("context") or "unknown"
                target = item.get("target")
                prefix = item.get("prefix")
                protocol = item.get("protocol")
                egress = (
                    item.get("egress_interface")
                    or item.get("interface")
                )

                detail = []

                if target:
                    detail.append(
                        f"next-hop {target}"
                    )

                if prefix:
                    detail.append(
                        f"route {prefix}"
                    )

                if protocol:
                    detail.append(
                        f"protocol {protocol}"
                    )

                if egress:
                    detail.append(
                        f"egress {egress}"
                    )

                lines.append(
                    f"  Firewall {context}: "
                    + " | ".join(detail)
                )

            elif stage == "router-route":

                router = item.get("router") or "unknown"
                vrf = item.get("vrf")
                prefix = item.get("prefix")
                protocol = item.get("protocol")
                next_hop = item.get("next_hop")
                interface = item.get("interface")

                detail = []

                if vrf:
                    detail.append(
                        f"VRF {vrf}"
                    )

                if prefix:
                    detail.append(
                        f"route {prefix}"
                    )

                if protocol:
                    detail.append(
                        f"protocol {protocol}"
                    )

                if next_hop:
                    detail.append(
                        f"next-hop {next_hop}"
                    )

                if interface:
                    detail.append(
                        f"egress {interface}"
                    )

                lines.append(
                    f"  Router {router}: "
                    + " | ".join(detail)
                )

            elif stage == "router-egress":

                router = item.get("router") or "unknown"
                vrf = item.get("vrf")
                egress = item.get("egress_interface")
                subnet = item.get("subnet")

                detail = []

                if vrf:
                    detail.append(
                        f"VRF {vrf}"
                    )

                if egress:
                    detail.append(
                        f"egress {egress}"
                    )

                if subnet:
                    detail.append(
                        f"subnet {subnet}"
                    )

                lines.append(
                    f"  Router egress {router}: "
                    + " | ".join(detail)
                )

            elif stage == "hsrp-next-hop-resolution":

                next_hop = item.get("next_hop")
                routers = item.get("routers") or []
                vrfs = item.get("vrfs") or []
                interfaces = item.get("interfaces") or []

                detail = []

                if next_hop:
                    detail.append(
                        f"VIP {next_hop}"
                    )

                if routers:
                    detail.append(
                        "routers "
                        + ", ".join(routers)
                    )

                if vrfs:
                    detail.append(
                        "VRF "
                        + ", ".join(vrfs)
                    )

                if interfaces:
                    detail.append(
                        "interfaces "
                        + ", ".join(interfaces)
                    )

                lines.append(
                    "  HSRP: "
                    + " | ".join(detail)
                )

            elif stage == "semantic-egress":

                context = item.get("context") or "unknown"
                egress = item.get("egress_interface")
                hint_type = item.get("hint_type")

                detail = []

                if egress:
                    detail.append(
                        f"egress {egress}"
                    )

                if hint_type:
                    detail.append(
                        f"classification {hint_type}"
                    )

                lines.append(
                    f"  Egress {context}: "
                    + " | ".join(detail)
                )

            elif stage == "inventory-boundary":

                device = (
                    item.get("router")
                    or item.get("context")
                    or "unknown"
                )

                next_hop = item.get("next_hop")
                reason = item.get("reason")

                detail = []

                if next_hop:
                    detail.append(
                        f"next-hop {next_hop}"
                    )

                if reason:
                    detail.append(reason)

                lines.append(
                    f"  Inventory boundary {device}: "
                    + " | ".join(detail)
                )

            elif stage == "routing-loop":

                context = (
                    item.get("router")
                    or item.get("context")
                    or "unknown"
                )

                lines.append(
                    f"  Routing loop detected at {context}"
                )

            elif stage == "traversal-limit":

                context = (
                    item.get("router")
                    or item.get("context")
                    or "unknown"
                )

                lines.append(
                    f"  Traversal limit reached at {context}"
                )

        return lines

    def render(self, report):

        lines = []

        lines.append("NETWORK DEPENDENCY REPORT")
        lines.append("=" * 80)
        lines.append("")

        lines.append(f"Network:   {report.network}")
        lines.append(f"Direction: {report.direction}")
        lines.append(f"Service:   {report.service or 'all'}")
        lines.append(f"Action:    {report.action}")
        lines.append("")

        lines.append("SUMMARY")
        lines.append("-" * 80)

        lines.append(
            f"Dependencies: {report.dependency_count}"
        )

        lines.append(
            f"Inbound:      {report.inbound_count}"
        )

        lines.append(
            f"Outbound:     {report.outbound_count}"
        )

        lines.append("")

        lines.append("EVIDENCE")
        lines.append("-" * 80)

        for evidence_class, count in sorted(
            report.evidence_class_counts.items()
        ):
            lines.append(
                f"{evidence_class}: {count}"
            )

        lines.append("")

        lines.append("FIREWALL POLICY USAGE")
        lines.append("-" * 80)

        policy_usage_labels = {
            "observed": "Rules with hits",
            "unobserved": "Rules without hits",
            "counter-unknown": "Hit count unavailable",
            "unknown": "Policy usage unknown",
        }

        for observation_state, count in sorted(
            report.observation_state_counts.items()
        ):
            label = policy_usage_labels.get(
                observation_state,
                observation_state
            )
            lines.append(
                f"{label}: {count}"
            )

        lines.append("")

        lines.append("CONFIDENCE")
        lines.append("-" * 80)

        lines.append(
            f"High:   {report.high_confidence_count}"
        )

        lines.append(
            f"Medium: {report.medium_confidence_count}"
        )

        lines.append(
            f"Low:    {report.low_confidence_count}"
        )

        lines.append("")

        lines.append("COVERAGE")
        lines.append("-" * 80)

        lines.append(
            f"Full:           {report.full_coverage_count}"
        )

        lines.append(
            f"Sampled:        {report.sampled_coverage_count}"
        )

        lines.append(
            "Not applicable: "
            f"{report.not_applicable_coverage_count}"
        )

        lines.append("")

        lines.append("TARGETS")
        lines.append("-" * 80)

        lines.append(
            f"Resolved:        {report.target_count}"
        )

        lines.append(
            f"Attempted:       {report.attempted_target_count}"
        )

        lines.append(
            f"Evidence-backed: {report.evidence_target_count}"
        )

        lines.append("")
        lines.append("DEPENDENCIES")
        lines.append("=" * 80)

        for entry in report.entries:

            dependency = entry.dependency
            hint = entry.hint
            state = entry.state

            lines.append("")
            lines.append(dependency.name)
            lines.append("-" * 80)

            lines.append(
                "Key: "
                f"{dependency.key}"
            )

            lines.append(
                "Evidence class: "
                f"{dependency.evidence_class}"
            )

            policy_usage_labels = {
                "observed": "Rule has hits",
                "unobserved": "Rule has no hits",
                "counter-unknown": "Hit count unavailable",
                "unknown": "Policy usage unknown",
            }

            lines.append(
                "Firewall policy usage: "
                + policy_usage_labels.get(
                    dependency.observation_state,
                    dependency.observation_state
                )
            )

            lines.append(
                "Direction: "
                + (
                    ", ".join(dependency.directions)
                    if dependency.directions
                    else "unknown"
                )
            )

            lines.append(
                "Services: "
                + (
                    ", ".join(dependency.services)
                    if dependency.services
                    else "unknown"
                )
            )

            lines.append(
                "Domain: "
                f"{dependency.domain}"
            )

            lines.append(
                "Resolved hosts: "
                + (
                    ", ".join(dependency.resolved_hosts)
                    if dependency.resolved_hosts
                    else "-"
                )
            )

            lines.append(
                "Resolved networks: "
                + (
                    ", ".join(dependency.resolved_networks)
                    if dependency.resolved_networks
                    else "-"
                )
            )

            lines.append(
                "Policy evidence contexts: "
                + (
                    ", ".join(dependency.contexts)
                    if dependency.contexts
                    else "-"
                )
            )

            if hint:

                lines.append(
                    "Path classification: "
                    f"{hint.hint_type}"
                )

                lines.append(
                    "Path value: "
                    f"{hint.hint_value or '-'}"
                )

                lines.append(
                    "Confidence: "
                    f"{hint.confidence}"
                )

                lines.append(
                    "Coverage: "
                    f"{hint.coverage}"
                )

                lines.append(
                    "Targets: "
                    f"{hint.target_count} total / "
                    f"{hint.attempted_target_count} attempted / "
                    f"{hint.evidence_target_count} evidence-backed"
                )

                lines.append(
                    "Reason: "
                    f"{hint.reason}"
                )

                lines.extend(
                    self._render_routing_path(
                        hint.evidence
                    )
                )

            else:

                lines.append(
                    "Path classification: unavailable"
                )

            if state:

                lines.append(
                    "Operational state: "
                    f"{state.operational_state}"
                )

                lines.append(
                    "State confidence: "
                    f"{state.confidence}"
                )

            else:

                lines.append(
                    "Operational state: unavailable"
                )

        lines.append("")

        return "\n".join(lines)
