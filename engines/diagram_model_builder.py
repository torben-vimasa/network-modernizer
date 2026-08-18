class DiagramModelBuilder:

    def build(
        self,
        application_model,
        collapse_groups=True
    ):

        application = (
            application_model.get(
                "application"
            )
            or "Unknown"
        )

        communications = (
            application_model.get(
                "communication",
                {}
            ).get(
                "communications",
                []
            )
        )

        nodes = {}
        edges = []

        #
        # Application root node.
        #
        app_id = f"application:{application}"

        nodes[app_id] = {
            "id": app_id,
            "type": "application",
            "label": application
        }

        for communication in communications:

            source = communication.get(
                "source",
                {}
            )

            destination = communication.get(
                "destination",
                {}
            )

            source_id = self._add_side_node(
                nodes,
                source,
                communication.get("context"),
                collapse_groups
            )

            destination_id = self._add_side_node(
                nodes,
                destination,
                communication.get("context"),
                collapse_groups
            )

            #
            # Application owns communication nodes.
            #
            self._add_edge(
                edges,
                app_id,
                source_id,
                "contains"
            )

            self._add_edge(
                edges,
                app_id,
                destination_id,
                "contains"
            )

            classifications = (
                communication.get(
                    "classification",
                    {}
                ).get(
                    "classifications",
                    []
                )
            )

            classification = None

            if classifications:
                classification = (
                    classifications[0]
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

            edge = {
                "source": source_id,
                "target": destination_id,
                "type": "communicates",
                "context": communication.get(
                    "context"
                ),
                "services": services,
                "logical_flows": communication.get(
                    "logical_flows",
                    0
                ),
                "evidence_count": communication.get(
                    "evidence_count",
                    0
                )
            }

            if classification:

                edge["classification"] = {
                    "service": classification.get(
                        "service"
                    ),
                    "domain": classification.get(
                        "domain"
                    ),
                    "category": classification.get(
                        "category"
                    ),
                    "confidence": classification.get(
                        "confidence"
                    )
                }

            edges.append(
                edge
            )

        return {
            "application": application,
            "summary": {
                "nodes": len(nodes),
                "edges": len(edges),
                "communications": sum(
                    1
                    for edge in edges
                    if edge.get("type")
                    == "communicates"
                )
            },
            "nodes": list(
                nodes.values()
            ),
            "edges": edges
        }


    def _add_side_node(
        self,
        nodes,
        side,
        context,
        collapse_groups
    ):

        reference = (
            side.get("reference")
            or "unknown"
        )

        groups = side.get(
            "groups",
            []
        )

        hosts = side.get(
            "hosts",
            []
        )

        networks = side.get(
            "networks",
            []
        )

        #
        # Prefer logical object/group node.
        #
        if (
            collapse_groups
            and groups
        ):

            node_id = (
                groups[0]
            )

            nodes[node_id] = {
                "id": node_id,
                "type": "object_group",
                "label": reference,
                "context": context,
                "member_count": (
                    len(hosts)
                    + len(networks)
                ),
                "host_count": len(
                    hosts
                ),
                "network_count": len(
                    networks
                ),
                "collapsed": True
            }

            return node_id

        #
        # Plain host.
        #
        if (
            len(hosts) == 1
            and not networks
        ):

            node_id = (
                f"host:{hosts[0]}"
            )

            nodes[node_id] = {
                "id": node_id,
                "type": "host",
                "label": reference,
                "ip": hosts[0],
                "context": context
            }

            return node_id

        #
        # Plain network.
        #
        if (
            len(networks) == 1
            and not hosts
        ):

            network = networks[0]

            if isinstance(
                network,
                dict
            ):
                network_value = (
                    network.get(
                        "network"
                    )
                )
            else:
                network_value = network

            node_id = (
                f"network:{network_value}"
            )

            nodes[node_id] = {
                "id": node_id,
                "type": "network",
                "label": reference,
                "network": network_value,
                "context": context
            }

            return node_id

        #
        # Generic aggregate.
        #
        node_id = (
            f"aggregate:{context}:{reference}"
        )

        nodes[node_id] = {
            "id": node_id,
            "type": "aggregate",
            "label": reference,
            "context": context,
            "host_count": len(
                hosts
            ),
            "network_count": len(
                networks
            ),
            "collapsed": True
        }

        return node_id


    def _add_edge(
        self,
        edges,
        source,
        target,
        edge_type
    ):

        key = (
            source,
            target,
            edge_type
        )

        for edge in edges:

            if (
                edge.get("source"),
                edge.get("target"),
                edge.get("type")
            ) == key:
                return

        edges.append({
            "source": source,
            "target": target,
            "type": edge_type
        })