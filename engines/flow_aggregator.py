from collections import defaultdict


class FlowAggregator:

    def aggregate(self, rules):

        logical_flows = {}
        pair_groups = defaultdict(list)
        service_families = defaultdict(list)

        #
        # Phase 1:
        # De-duplicate identical logical ACL flows.
        #
        for item in rules:

            properties = item.get(
                "properties",
                {}
            )

            context = properties.get("context")

            source = (
                properties.get("source_value")
                or properties.get("source")
            )

            destination = (
                properties.get("destination_value")
                or properties.get("destination")
            )

            protocol = properties.get("protocol")
            service = properties.get("service")
            action = properties.get("action")

            key = (
                context,
                action,
                protocol,
                source,
                destination,
                service
            )

            if key not in logical_flows:

                logical_flows[key] = {
                    "context": context,
                    "action": action,
                    "protocol": protocol,
                    "source": source,
                    "destination": destination,
                    "service": service,
                    "evidence": []
                }

            logical_flows[key]["evidence"].append({
                "name": item.get("name"),
                "acl": properties.get("acl"),
                "sequence": properties.get(
                    "sequence"
                ),
                "hitcnt": properties.get(
                    "hitcnt"
                ),
                "raw": properties.get(
                    "raw"
                )
            })

        #
        # Phase 2:
        # Group communication by source/destination pair.
        #
        for flow in logical_flows.values():

            pair_key = (
                flow["context"],
                flow["source"],
                flow["destination"]
            )

            pair_groups[pair_key].append(
                flow
            )

            service_key = (
                flow["context"],
                flow["destination"],
                flow["protocol"],
                flow["service"]
            )

            service_families[
                service_key
            ].append(
                flow["source"]
            )

        #
        # Build pair view.
        #
        communication_pairs = []

        for (
            context,
            source,
            destination
        ), flows in pair_groups.items():

            services = []
            evidence_count = 0
            hitcnt = 0
            hitcnt_known = False

            for flow in flows:

                service_entry = {
                    "protocol": flow[
                        "protocol"
                    ],
                    "service": flow[
                        "service"
                    ],
                    "action": flow[
                        "action"
                    ]
                }

                if (
                    service_entry
                    not in services
                ):
                    services.append(
                        service_entry
                    )

                evidence_count += len(
                    flow["evidence"]
                )

                for evidence in flow[
                    "evidence"
                ]:

                    value = evidence.get(
                        "hitcnt"
                    )

                    if value is None:
                        continue

                    hitcnt_known = True
                    hitcnt += value

            communication_pairs.append({
                "context": context,
                "source": source,
                "destination": destination,
                "services": services,
                "logical_flows": len(flows),
                "evidence_count": evidence_count,
                "hitcnt": (
                    hitcnt
                    if hitcnt_known
                    else None
                )
            })

        #
        # Build destination/service family view.
        #
        families = []

        for (
            context,
            destination,
            protocol,
            service
        ), sources in service_families.items():

            unique_sources = sorted(
                set(sources)
            )

            families.append({
                "context": context,
                "destination": destination,
                "protocol": protocol,
                "service": service,
                "sources": unique_sources,
                "source_count": len(
                    unique_sources
                )
            })

        communication_pairs.sort(
            key=lambda item: (
                str(item.get("context")),
                str(item.get("source")),
                str(item.get("destination"))
            )
        )

        families.sort(
            key=lambda item: (
                -item["source_count"],
                str(item.get("context")),
                str(item.get("destination"))
            )
        )

        return {
            "raw_rules": len(rules),
            "logical_flows": len(
                logical_flows
            ),
            "communication_pairs": (
                communication_pairs
            ),
            "service_families": families,
            "summary": {
                "raw_rules": len(rules),
                "logical_flows": len(
                    logical_flows
                ),
                "communication_pairs": len(
                    communication_pairs
                ),
                "service_families": len(
                    families
                )
            }
        }