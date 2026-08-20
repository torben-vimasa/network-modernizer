class FlowCoverageAnalyzer:

    def __init__(
        self,
        flow_trace_engine,
        max_trace_pairs=32
    ):
        self.flow_trace_engine = (
            flow_trace_engine
        )

        self.max_trace_pairs = (
            max_trace_pairs
        )


    def analyze(
        self,
        application_model
    ):

        communications = (
            application_model.get(
                "communication",
                {}
            ).get(
                "communications",
                []
            )
        )

        records = []

        summary = {
            "communications": len(
                communications
            ),
            "flows_evaluated": 0,
            "fully_traced": 0,
            "inventory_boundary": 0,
            "unresolved": 0,
            "not_traceable": 0,
            "skipped_expansion_limit": 0
        }

        for communication in communications:

            source_hosts = (
                self._concrete_hosts(
                    communication.get(
                        "source",
                        {}
                    )
                )
            )

            destination_hosts = (
                self._concrete_hosts(
                    communication.get(
                        "destination",
                        {}
                    )
                )
            )

            if (
                not source_hosts
                or not destination_hosts
            ):

                summary[
                    "not_traceable"
                ] += 1

                records.append({
                    "classification": (
                        "not_traceable"
                    ),
                    "source": (
                        communication.get(
                            "source",
                            {}
                        ).get(
                            "reference"
                        )
                    ),
                    "destination": (
                        communication.get(
                            "destination",
                            {}
                        ).get(
                            "reference"
                        )
                    ),
                    "reason": (
                        "Communication has no "
                        "concrete host-to-host "
                        "pair available for tracing."
                    )
                })

                continue

            pair_count = (
                len(source_hosts)
                * len(destination_hosts)
            )

            if (
                pair_count
                > self.max_trace_pairs
            ):

                summary[
                    "skipped_expansion_limit"
                ] += 1

                records.append({
                    "classification": (
                        "not_traceable"
                    ),
                    "source": (
                        communication.get(
                            "source",
                            {}
                        ).get(
                            "reference"
                        )
                    ),
                    "destination": (
                        communication.get(
                            "destination",
                            {}
                        ).get(
                            "reference"
                        )
                    ),
                    "reason": (
                        f"Communication expands to "
                        f"{pair_count} host pairs, "
                        f"above limit "
                        f"{self.max_trace_pairs}."
                    )
                })

                continue

            for source_ip in source_hosts:

                for destination_ip in (
                    destination_hosts
                ):

                    summary[
                        "flows_evaluated"
                    ] += 1

                    trace = (
                        self.flow_trace_engine.trace(
                            source_ip,
                            destination_ip
                        )
                    )

                    record = (
                        self._record_from_trace(
                            source_ip,
                            destination_ip,
                            trace
                        )
                    )

                    summary[
                        record[
                            "classification"
                        ]
                    ] += 1

                    records.append(
                        record
                    )

        return {
            "summary": summary,
            "records": records
        }


    def _record_from_trace(
        self,
        source,
        destination,
        trace
    ):

        paths = trace.get(
            "paths",
            []
        )

        if not paths:

            return {
                "classification": (
                    "unresolved"
                ),
                "source": source,
                "destination": destination,
                "confidence": (
                    trace.get(
                        "confidence"
                    )
                ),
                "last_device": None,
                "vrf": None,
                "route_prefix": None,
                "route_protocol": None,
                "next_hop": None,
                "forwarding_method": None,
                "status": None,
                "reason": trace.get(
                    "reason"
                )
            }

        #
        # Current engine normally provides
        # one deterministic source path.
        #
        path = paths[0]

        hops = path.get(
            "hops",
            []
        )

        last_hop = (
            hops[-1]
            if hops
            else {}
        )

        route = (
            last_hop.get(
                "route"
            )
            or {}
        )

        forwarding = (
            last_hop.get(
                "forwarding"
            )
            or {}
        )

        if path.get(
            "destination_reached"
        ):

            classification = (
                "fully_traced"
            )

        elif path.get(
            "inventory_boundary"
        ):

            classification = (
                "inventory_boundary"
            )

        else:

            classification = (
                "unresolved"
            )

        return {
            "classification": (
                classification
            ),
            "source": source,
            "destination": destination,
            "confidence": (
                trace.get(
                    "confidence"
                )
            ),
            "last_device": (
                last_hop.get(
                    "device"
                )
            ),
            "device_type": (
                last_hop.get(
                    "device_type"
                )
            ),
            "vrf": (
                last_hop.get(
                    "vrf"
                )
            ),
            "route_prefix": (
                route.get(
                    "prefix"
                )
            ),
            "route_protocol": (
                route.get(
                    "protocol"
                )
            ),
            "next_hop": (
                route.get(
                    "next_hop"
                )
            ),
            "forwarding_method": (
                forwarding.get(
                    "method"
                )
            ),
            "status": (
                last_hop.get(
                    "status"
                )
            ),
            "reason": (
                path.get(
                    "reason"
                )
                or trace.get(
                    "reason"
                )
            ),
            "firewalls": (
                path.get(
                    "firewalls",
                    []
                )
            ),
            "routers": (
                path.get(
                    "routers",
                    []
                )
            ),
            "vrfs": (
                path.get(
                    "vrfs",
                    []
                )
            )
        }


    def _concrete_hosts(
        self,
        side
    ):

        result = []

        for host in side.get(
            "hosts",
            []
        ):

            if host:
                result.append(
                    str(host)
                )

        for endpoint in side.get(
            "endpoints",
            []
        ):

            value = endpoint.get(
                "endpoint"
            )

            if value:
                result.append(
                    str(value)
                )

        return self._unique(
            result
        )


    def _unique(
        self,
        values
    ):

        result = []
        seen = set()

        for value in values:

            if not value:
                continue

            if value in seen:
                continue

            seen.add(
                value
            )

            result.append(
                value
            )

        return result