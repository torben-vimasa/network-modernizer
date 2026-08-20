class MermaidRenderer:

    FORWARDING_EDGE_TYPES = {
        "application_endpoint",
        "forwarding_path",
        "destination_reached",
        "inventory_boundary",
        "external_destination"
    }

    DEPENDENCY_EDGE_TYPES = {
        "depends_on",
        "has_interface",
        "via_interface",
        "redundancy_member",
        "forwarding_vrf"
    }


    def render(
        self,
        diagram,
        mode="auto"
    ):

        lines = [
            "flowchart LR"
        ]

        diagram_nodes = diagram.get(
            "nodes",
            []
        )

        edges = diagram.get(
            "edges",
            []
        )

        effective_mode = (
            self._resolve_mode(
                mode,
                edges
            )
        )

        visible_edges = (
            self._visible_edges(
                edges,
                effective_mode
            )
        )

        if effective_mode == "forwarding_compact":

            visible_edges = (
                self._aggregate_forwarding_edges(
                    visible_edges
                )
            )

        visible_node_ids = (
            self._visible_node_ids(
                diagram_nodes,
                visible_edges,
                effective_mode
            )
        )

        visible_nodes = [
            node
            for node in diagram_nodes
            if node.get("id")
            in visible_node_ids
        ]

        node_ids = {}

        for index, node in enumerate(
            visible_nodes,
            start=1
        ):
            node_ids[node["id"]] = (
                f"N{index}"
            )

        root_nodes = []
        context_nodes = {}
        ungrouped_nodes = []

        for node in visible_nodes:

            if node.get("type") == "application":
                root_nodes.append(node)
                continue

            context = node.get(
                "context"
            )

            if context:
                context_nodes.setdefault(
                    context,
                    []
                ).append(node)
            else:
                ungrouped_nodes.append(
                    node
                )

        for node in root_nodes:

            lines.append(
                "    "
                + self._render_node(
                    node,
                    node_ids
                )
            )

        if root_nodes:
            lines.append("")

        for context in sorted(
            context_nodes.keys()
        ):

            context_id = (
                self._safe_subgraph_id(
                    context
                )
            )

            context_label = (
                self._escape(
                    context
                )
            )

            lines.append(
                f'    subgraph '
                f'{context_id}'
                f'["{context_label}"]'
            )

            lines.append(
                "        direction LR"
            )

            for node in context_nodes[
                context
            ]:

                lines.append(
                    "        "
                    + self._render_node(
                        node,
                        node_ids
                    )
                )

            lines.append(
                "    end"
            )

            lines.append("")

        for node in ungrouped_nodes:

            lines.append(
                "    "
                + self._render_node(
                    node,
                    node_ids
                )
            )

        if ungrouped_nodes:
            lines.append("")

        for edge in visible_edges:

            source = node_ids.get(
                edge.get(
                    "source"
                )
            )

            target = node_ids.get(
                edge.get(
                    "target"
                )
            )

            if not source or not target:
                continue

            label = (
                self._edge_label(
                    edge
                )
            )

            arrow = (
                self._edge_arrow(
                    edge
                )
            )

            if label:

                lines.append(
                    f'    {source} '
                    f'{arrow}'
                    f'|"{label}"| '
                    f'{target}'
                )

            else:

                lines.append(
                    f"    {source} "
                    f"{arrow} "
                    f"{target}"
                )

        return "\n".join(
            lines
        )


    def _resolve_mode(
        self,
        mode,
        edges
    ):

        if mode != "auto":
            return mode

        forwarding_count = sum(
            1
            for edge in edges
            if edge.get("type")
            in self.FORWARDING_EDGE_TYPES
        )

        if forwarding_count:

            if forwarding_count > 25:
                return "forwarding_compact"

            return "forwarding"

        if any(
            edge.get("type")
            == "communicates"
            for edge in edges
        ):
            return "communications"

        return "dependency"


    def _visible_edges(
        self,
        edges,
        mode
    ):

        if mode == "all":
            return list(
                edges
            )

        if mode == "communications":

            return [
                edge
                for edge in edges
                if edge.get(
                    "type"
                ) == "communicates"
            ]

        if mode in [
            "forwarding",
            "forwarding_compact"
        ]:

            return [
                edge
                for edge in edges
                if edge.get(
                    "type"
                )
                in self.FORWARDING_EDGE_TYPES
            ]

        if mode == "dependency":

            return [
                edge
                for edge in edges
                if edge.get(
                    "type"
                )
                in self.DEPENDENCY_EDGE_TYPES
            ]

        return list(
            edges
        )


    def _aggregate_forwarding_edges(
        self,
        edges
    ):

        groups = {}

        for edge in edges:

            edge_type = edge.get(
                "type"
            )

            properties = dict(
                edge.get(
                    "properties"
                )
                or {}
            )

            source = edge.get(
                "source"
            )

            target = edge.get(
                "target"
            )

            if edge_type == "forwarding_path":

                key = (
                    source,
                    target,
                    edge_type,
                    properties.get("vrf"),
                    properties.get(
                        "next_hop"
                    ),
                    properties.get(
                        "forwarding_method"
                    ),
                    properties.get("status")
                )

            elif edge_type == "inventory_boundary":

                key = (
                    source,
                    target,
                    edge_type,
                    properties.get(
                        "next_hop"
                    )
                )

            else:

                key = (
                    source,
                    target,
                    edge_type
                )

            if key not in groups:

                groups[key] = {
                    "source": source,
                    "target": target,
                    "type": edge_type,
                    "properties": {
                        "vrf": properties.get(
                            "vrf"
                        ),
                        "next_hop": (
                            properties.get(
                                "next_hop"
                            )
                        ),
                        "forwarding_method": (
                            properties.get(
                                "forwarding_method"
                            )
                        ),
                        "status": (
                            properties.get(
                                "status"
                            )
                        ),
                        "confidence": (
                            properties.get(
                                "confidence"
                            )
                        ),
                        "prefixes": set(),
                        "protocols": set(),
                        "flows": set()
                    }
                }

            compact = groups[
                key
            ]["properties"]

            flow_key = (
                properties.get("source"),
                properties.get(
                    "destination"
                )
            )

            if any(flow_key):
                compact["flows"].add(
                    flow_key
                )

            prefix = properties.get(
                "prefix"
            )

            if prefix:
                compact[
                    "prefixes"
                ].add(prefix)

            protocol = properties.get(
                "protocol"
            )

            if protocol:
                compact[
                    "protocols"
                ].add(protocol)

        result = []

        for group in groups.values():

            properties = group[
                "properties"
            ]

            flows = properties.pop(
                "flows"
            )

            properties[
                "flow_count"
            ] = max(
                len(flows),
                1
            )

            properties[
                "prefixes"
            ] = sorted(
                properties[
                    "prefixes"
                ]
            )

            properties[
                "protocols"
            ] = sorted(
                properties[
                    "protocols"
                ]
            )

            result.append(
                group
            )

        return result


    def _visible_node_ids(
        self,
        nodes,
        edges,
        mode
    ):

        result = set()

        for edge in edges:

            source = edge.get(
                "source"
            )

            target = edge.get(
                "target"
            )

            if source:
                result.add(
                    source
                )

            if target:
                result.add(
                    target
                )

        for node in nodes:

            if node.get(
                "type"
            ) == "application":

                result.add(
                    node.get(
                        "id"
                    )
                )

        if mode == "communications":

            for node in nodes:

                if node.get(
                    "type"
                ) in [
                    "host",
                    "network",
                    "object_group",
                    "aggregate"
                ]:

                    result.add(
                        node.get(
                            "id"
                        )
                    )

        return result


    def _render_node(
        self,
        node,
        node_ids
    ):

        node_id = node_ids[
            node["id"]
        ]

        label = self._node_label(
            node
        )

        return self._node_shape(
            node_id,
            label,
            node.get(
                "type"
            )
        )


    def _node_label(
        self,
        node
    ):

        label = str(
            node.get(
                "label",
                node.get(
                    "id",
                    "unknown"
                )
            )
        )

        node_type = node.get(
            "type"
        )

        if node_type == "object_group":

            members = node.get(
                "member_count",
                0
            )

            hosts = node.get(
                "host_count",
                0
            )

            networks = node.get(
                "network_count",
                0
            )

            return (
                f"{label}"
                f"<br/>{members} members"
                f"<br/>{hosts} hosts / "
                f"{networks} networks"
            )

        if (
            node_type == "host"
            and node.get("ip")
            and node.get("ip") != label
        ):

            label += (
                f"<br/>{node['ip']}"
            )

        if node_type == "network":

            network = node.get(
                "network"
            )

            if (
                network
                and network != label
            ):

                label += (
                    f"<br/>{network}"
                )

        if node_type == "aggregate":

            hosts = node.get(
                "host_count",
                0
            )

            networks = node.get(
                "network_count",
                0
            )

            label += (
                f"<br/>{hosts} hosts / "
                f"{networks} networks"
            )

        if node_type == "endpoint":

            role = node.get(
                "role"
            )

            if role:
                label += (
                    f"<br/>{role}"
                )

        if node_type == "vrf":

            label = (
                f"VRF<br/>{label}"
            )

        if node_type == "firewall":

            label = (
                f"FW<br/>{label}"
            )

        if node_type == "router":

            label = (
                f"Router<br/>{label}"
            )

        if node_type == "redundancy":

            label = (
                f"Redundancy<br/>{label}"
            )

        if node_type == (
            "inventory_boundary"
        ):

            if not label.lower().startswith(
                "inventory boundary"
            ):

                label = (
                    "Inventory boundary"
                    f"<br/>{label}"
                )

        return label


    def _node_shape(
        self,
        node_id,
        label,
        node_type
    ):

        label = self._escape(
            label
        )

        if node_type == "application":

            return (
                f'{node_id}(["{label}"])'
            )

        if node_type == "object_group":

            return (
                f'{node_id}[["{label}"]]'
            )

        if node_type == "network":

            return (
                f'{node_id}[("{label}")]'
            )

        if node_type == "aggregate":

            return (
                f'{node_id}{{"{label}"}}'
            )

        if node_type == "firewall":

            return (
                f'{node_id}[["{label}"]]'
            )

        if node_type == "router":

            return (
                f'{node_id}("{label}")'
            )

        if node_type == "vrf":

            return (
                f'{node_id}{{"{label}"}}'
            )

        if node_type in [
            "redundancy",
            "inventory_boundary"
        ]:

            return (
                f'{node_id}{{{{"{label}"}}}}'
            )

        return (
            f'{node_id}["{label}"]'
        )


    def _edge_arrow(
        self,
        edge
    ):

        edge_type = edge.get(
            "type"
        )

        if edge_type == (
            "external_destination"
        ):

            return "-.->"

        return "-->"


    def _edge_label(
        self,
        edge
    ):

        edge_type = edge.get(
            "type"
        )

        if edge_type == "communicates":

            classification = (
                edge.get(
                    "classification"
                )
                or {}
            )

            service_name = (
                classification.get(
                    "service"
                )
            )

            services = edge.get(
                "services",
                []
            )

            parts = []

            if service_name:
                parts.append(
                    str(service_name)
                )

            if services:

                parts.append(
                    ", ".join(
                        str(service)
                        for service in services
                    )
                )

            return "<br/>".join(
                self._escape(
                    part
                )
                for part in parts
            )

        properties = (
            edge.get(
                "properties"
            )
            or {}
        )

        if edge_type == "application_endpoint":
            return ""

        if edge_type == "forwarding_path":

            parts = []

            flow_count = properties.get(
                "flow_count"
            )

            if (
                flow_count
                and flow_count > 1
            ):

                parts.append(
                    f"{flow_count} flows"
                )

            vrf = properties.get(
                "vrf"
            )

            next_hop = properties.get(
                "next_hop"
            )

            forwarding_method = (
                properties.get(
                    "forwarding_method"
                )
            )

            prefixes = properties.get(
                "prefixes"
            )

            if prefixes is None:

                prefix = properties.get(
                    "prefix"
                )

                prefixes = (
                    [prefix]
                    if prefix
                    else []
                )

            protocols = properties.get(
                "protocols"
            )

            if protocols is None:

                protocol = properties.get(
                    "protocol"
                )

                protocols = (
                    [protocol]
                    if protocol
                    else []
                )

            if vrf:
                parts.append(
                    f"VRF {vrf}"
                )

            if len(prefixes) == 1:

                prefix_text = (
                    prefixes[0]
                )

                if len(protocols) == 1:

                    prefix_text += (
                        f" ({protocols[0]})"
                    )

                parts.append(
                    prefix_text
                )

            elif len(prefixes) > 1:

                parts.append(
                    f"{len(prefixes)} route prefixes"
                )

            if next_hop:
                parts.append(
                    f"NH {next_hop}"
                )

            if forwarding_method:
                parts.append(
                    str(
                        forwarding_method
                    )
                )

            return "<br/>".join(
                self._escape(
                    part
                )
                for part in parts
            )

        if edge_type == (
            "destination_reached"
        ):

            confidence = (
                properties.get(
                    "confidence"
                )
            )

            if confidence:

                return self._escape(
                    f"destination reached "
                    f"({confidence})"
                )

            return (
                "destination reached"
            )

        if edge_type == (
            "inventory_boundary"
        ):

            next_hop = (
                properties.get(
                    "next_hop"
                )
            )

            if next_hop:

                return self._escape(
                    f"inventory boundary"
                    f"<br/>NH {next_hop}"
                )

            return (
                "inventory boundary"
            )

        if edge_type == (
            "external_destination"
        ):

            confidence = (
                properties.get(
                    "confidence"
                )
            )

            if confidence:

                return self._escape(
                    f"external destination "
                    f"({confidence})"
                )

            return (
                "external destination"
            )

        if edge_type:

            return self._escape(
                edge_type.replace(
                    "_",
                    " "
                )
            )

        return ""


    def _safe_subgraph_id(
        self,
        value
    ):

        safe = "".join(
            character
            if character.isalnum()
            else "_"
            for character in str(
                value
            )
        )

        return (
            f"CTX_{safe}"
        )


    def _escape(
        self,
        value
    ):

        return (
            str(value)
            .replace('"', "'")
            .replace("\n", " ")
        )
