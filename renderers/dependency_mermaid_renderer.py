class DependencyMermaidRenderer:

    def render(self, diagram):

        lines = [
            "flowchart LR"
        ]

        nodes = diagram.get(
            "nodes",
            []
        )

        edges = diagram.get(
            "edges",
            []
        )

        node_ids = {
            node["id"]: f"N{index}"
            for index, node in enumerate(
                nodes,
                start=1
            )
        }

        #
        # Render nodes grouped by type.
        #
        type_groups = {}

        for node in nodes:

            node_type = (
                node.get("type")
                or "unknown"
            )

            type_groups.setdefault(
                node_type,
                []
            ).append(node)

        #
        # Application root outside subgraphs.
        #
        for node in type_groups.get(
            "application",
            []
        ):

            lines.append(
                "    "
                + self._render_node(
                    node,
                    node_ids
                )
            )

        lines.append("")

        #
        # Infrastructure groups.
        #
        group_order = [
            "firewall",
            "router",
            "vrf",
            "redundancy",
            "interface"
        ]

        for node_type in group_order:

            group = type_groups.get(
                node_type,
                []
            )

            if not group:
                continue

            group_id = (
                f"TYPE_{node_type.upper()}"
            )

            title = (
                node_type
                .replace("_", " ")
                .title()
            )

            lines.append(
                f'    subgraph {group_id}["{title}s"]'
            )

            lines.append(
                "        direction TB"
            )

            for node in group:

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
        # Other node types.
        #
        known_types = set(
            group_order
            + ["application"]
        )

        for node_type, group in sorted(
            type_groups.items()
        ):

            if node_type in known_types:
                continue

            for node in group:

                lines.append(
                    "    "
                    + self._render_node(
                        node,
                        node_ids
                    )
                )

        lines.append("")

        #
        # Edges.
        #
        seen_visual_edges = set()

        for edge in edges:

            source = node_ids.get(
                edge.get("source")
            )

            target = node_ids.get(
                edge.get("target")
            )

            if not source or not target:
                continue

            edge_type = edge.get(
                "type",
                "dependency"
            )

            #
            # has_interface and via_interface
            # represent the same visible connection.
            #
            visual_type = edge_type

            if edge_type in [
                "has_interface",
                "via_interface"
            ]:
                visual_type = "interface"

            visual_key = (
                source,
                target,
                visual_type
            )

            if visual_key in seen_visual_edges:
                continue

            seen_visual_edges.add(
                visual_key
            )

            label = self._edge_label(
                edge_type
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

        label = self._escape(
            node.get(
                "label",
                node["id"]
            )
        )

        node_type = node.get(
            "type"
        )

        if node_type == "application":

            return (
                f'{node_id}(["{label}"])'
            )

        if node_type == "firewall":

            return (
                f'{node_id}{{{{"{label}"}}}}'
            )

        if node_type == "router":

            return (
                f'{node_id}[("{label}")]'
            )

        if node_type == "vrf":

            return (
                f'{node_id}[["VRF<br/>{label}"]]'
            )

        if node_type == "redundancy":

            return (
                f'{node_id}(["HSRP / VIP'
                f'<br/>{label}"])'
            )

        if node_type == "interface":

            return (
                f'{node_id}["{label}"]'
            )

        return (
            f'{node_id}["{label}"]'
        )


    def _edge_label(
        self,
        edge_type
    ):

        labels = {
            "depends_on": "depends on",
            "has_interface": "interface",
            "via_interface": "interface",
            "redundancy_member": "member"
        }

        return labels.get(
            edge_type,
            edge_type.replace(
                "_",
                " "
            )
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