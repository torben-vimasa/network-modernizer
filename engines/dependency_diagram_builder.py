class DependencyDiagramBuilder:

    def build(self, application_model):

        application = (
            application_model.get("application")
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

        app_id = f"application:{application}"

        nodes[app_id] = {
            "id": app_id,
            "type": "application",
            "label": application
        }

        for communication in communications:

            dependencies = communication.get(
                "infrastructure_dependencies",
                {}
            )

            combined = dependencies.get(
                "combined_dependencies",
                {}
            )

            self._add_dependency_nodes(
                nodes,
                edges,
                app_id,
                combined
            )

        return {
            "application": application,
            "summary": {
                "nodes": len(nodes),
                "edges": len(edges)
            },
            "nodes": list(nodes.values()),
            "edges": edges
        }


    def _add_dependency_nodes(
        self,
        nodes,
        edges,
        app_id,
        dependencies
    ):

        firewall_ids = []
        router_ids = []
        vrf_ids = []
        interface_ids = []
        redundancy_ids = []

        #
        # Firewalls
        #
        for name in dependencies.get(
            "firewalls",
            []
        ):

            node_id = f"firewall:{name}"

            nodes[node_id] = {
                "id": node_id,
                "type": "firewall",
                "label": name
            }

            firewall_ids.append(node_id)

            self._add_edge(
                edges,
                app_id,
                node_id,
                "depends_on"
            )

        #
        # Routers
        #
        for name in dependencies.get(
            "routers",
            []
        ):

            node_id = f"router:{name}"

            nodes[node_id] = {
                "id": node_id,
                "type": "router",
                "label": name
            }

            router_ids.append(node_id)

            self._add_edge(
                edges,
                app_id,
                node_id,
                "depends_on"
            )

        #
        # VRFs
        #
        for name in dependencies.get(
            "vrfs",
            []
        ):

            node_id = f"vrf:{name}"

            nodes[node_id] = {
                "id": node_id,
                "type": "vrf",
                "label": name
            }

            vrf_ids.append(node_id)

        #
        # Interfaces
        #
        for name in dependencies.get(
            "interfaces",
            []
        ):

            node_id = f"interface:{name}"

            nodes[node_id] = {
                "id": node_id,
                "type": "interface",
                "label": name
            }

            interface_ids.append(node_id)

        #
        # Redundancy groups
        #
        for group in dependencies.get(
            "redundancy_groups",
            []
        ):

            virtual_ip = group.get(
                "virtual_ip"
            )

            if not virtual_ip:
                continue

            node_id = (
                f"redundancy:{virtual_ip}"
            )

            nodes[node_id] = {
                "id": node_id,
                "type": "redundancy",
                "label": virtual_ip
            }

            redundancy_ids.append(
                node_id
            )

            for member in group.get(
                "members",
                []
            ):

                router = member.get(
                    "router"
                )

                interface = member.get(
                    "interface"
                )

                if router:

                    router_id = (
                        f"router:{router}"
                    )

                    nodes.setdefault(
                        router_id,
                        {
                            "id": router_id,
                            "type": "router",
                            "label": router
                        }
                    )

                    self._add_edge(
                        edges,
                        node_id,
                        router_id,
                        "redundancy_member"
                    )

                if (
                    router
                    and interface
                ):

                    interface_name = (
                        f"{router}:{interface}"
                    )

                    interface_id = (
                        f"interface:{interface_name}"
                    )

                    nodes.setdefault(
                        interface_id,
                        {
                            "id": interface_id,
                            "type": "interface",
                            "label": interface_name
                        }
                    )

                    self._add_edge(
                        edges,
                        router_id,
                        interface_id,
                        "via_interface"
                    )

        #
        # Generic relationships.
        #
        for vrf_id in vrf_ids:

            self._add_edge(
                edges,
                app_id,
                vrf_id,
                "depends_on"
            )

        for interface_id in interface_ids:

            owner = self._interface_owner(
                interface_id
            )

            if not owner:
                continue

            firewall_id = (
                f"firewall:{owner}"
            )

            router_id = (
                f"router:{owner}"
            )

            if firewall_id in nodes:

                self._add_edge(
                    edges,
                    firewall_id,
                    interface_id,
                    "has_interface"
                )

            if router_id in nodes:

                self._add_edge(
                    edges,
                    router_id,
                    interface_id,
                    "has_interface"
                )


    def _interface_owner(
        self,
        interface_id
    ):

        value = interface_id.removeprefix(
            "interface:"
        )

        if ":" not in value:
            return None

        return value.split(
            ":",
            1
        )[0]


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