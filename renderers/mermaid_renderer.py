class MermaidRenderer:

    def render(self, diagram):

        lines = [
            "flowchart LR"
        ]

        diagram_nodes = diagram.get(
            "nodes",
            []
        )

        node_ids = {}

        #
        # Mermaid-safe node IDs.
        #
        for index, node in enumerate(
            diagram_nodes,
            start=1
        ):
            node_ids[node["id"]] = (
                f"N{index}"
            )

        #
        # Separate application/root nodes
        # from context-owned nodes.
        #
        root_nodes = []
        context_nodes = {}
        ungrouped_nodes = []

        for node in diagram_nodes:

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

        #
        # Application/root nodes.
        #
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

        #
        # Context subgraphs.
        #
        for context in sorted(
            context_nodes.keys()
        ):

            context_id = (
                self._safe_subgraph_id(
                    context
                )
            )

            context_label = (
                self._escape(context)
            )

            lines.append(
                f'    subgraph {context_id}["{context_label}"]'
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

        #
        # Nodes without context.
        #
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

        #
        # Communication edges only.
        #
        for edge in diagram.get(
            "edges",
            []
        ):

            if (
                edge.get("type")
                != "communicates"
            ):
                continue

            source = node_ids.get(
                edge.get("source")
            )

            target = node_ids.get(
                edge.get("target")
            )

            if not source or not target:
                continue

            label = self._edge_label(
                edge
            )

            if label:
                lines.append(
                    f'    {source} '
                    f'-->|"{label}"| '
                    f'{target}'
                )
            else:
                lines.append(
                    f"    {source} --> {target}"
                )

        return "\n".join(
            lines
        )


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
            node.get("type")
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

        #
        # Context is represented by the
        # Mermaid subgraph, so do not repeat
        # it inside every node.
        #
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

        return (
            f'{node_id}["{label}"]'
        )


    def _edge_label(
        self,
        edge
    ):

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
            self._escape(part)
            for part in parts
        )


    def _safe_subgraph_id(
        self,
        value
    ):

        safe = "".join(
            character
            if character.isalnum()
            else "_"
            for character in str(value)
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