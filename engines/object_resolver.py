import ipaddress


class ObjectResolver:

    def __init__(self, graph):
        self.graph = graph


    def resolve(
        self,
        value,
        context=None,
        max_depth=10
    ):

        result = {
            "input": value,
            "context": context,
            "resolved": False,
            "hosts": [],
            "networks": [],
            "objects": [],
            "groups": [],
            "unresolved": [],
            "evidence": []
        }

        if not value:
            return result

        #
        # Direct IP/network first.
        #
        direct = self._parse_address(value)

        if direct:

            if direct["type"] == "host":
                result["hosts"].append(
                    direct["value"]
                )

            else:
                result["networks"].append(
                    direct["value"]
                )

            result["resolved"] = True
            return result

        #
        # Resolve graph object/group references.
        #
        visited = set()

        self._resolve_reference(
            value=value,
            context=context,
            depth=0,
            max_depth=max_depth,
            visited=visited,
            result=result
        )

        result["hosts"] = sorted(
            set(result["hosts"]),
            key=self._ip_sort_key
        )

        result["networks"] = sorted(
            set(result["networks"]),
            key=self._network_sort_key
        )

        result["objects"] = sorted(
            set(result["objects"])
        )

        result["groups"] = sorted(
            set(result["groups"])
        )

        result["unresolved"] = sorted(
            set(result["unresolved"])
        )

        result["resolved"] = bool(
            result["hosts"]
            or result["networks"]
            or result["objects"]
            or result["groups"]
        )

        return result


    def _resolve_reference(
        self,
        value,
        context,
        depth,
        max_depth,
        visited,
        result
    ):

        if depth > max_depth:
            result["unresolved"].append(
                value
            )
            return

        candidates = self._find_candidates(
            value,
            context
        )

        if not candidates:

            parsed = self._parse_address(
                value
            )

            if parsed:

                if parsed["type"] == "host":
                    result["hosts"].append(
                        parsed["value"]
                    )

                else:
                    result["networks"].append(
                        parsed["value"]
                    )

                return

            result["unresolved"].append(
                value
            )
            return

        for node in candidates:

            if node.id in visited:
                continue

            visited.add(node.id)

            result["evidence"].append({
                "type": node.type,
                "name": node.name,
                "properties": node.properties
            })

            #
            # Plain network object.
            #
            if node.type == "NetworkObject":

                result["objects"].append(
                    node.name
                )

                self._consume_network_object(
                    node,
                    result
                )

                continue

            #
            # Object-group.
            #
            if node.type != "ObjectGroup":
                continue

            result["groups"].append(
                node.name
            )

            #
            # Follow:
            #
            # ObjectGroup -> HAS_MEMBER -> member
            #
            for relationship in self.graph.relationships:

                source = getattr(
                    relationship.source,
                    "id",
                    relationship.source
                )

                target = getattr(
                    relationship.target,
                    "id",
                    relationship.target
                )

                if relationship.type != "HAS_MEMBER":
                    continue

                if source != node.id:
                    continue

                member = self.graph.nodes.get(
                    target
                )

                if not member:
                    continue

                if member.type == "NetworkObject":

                    if member.id in visited:
                        continue

                    visited.add(
                        member.id
                    )

                    result["evidence"].append({
                        "type": member.type,
                        "name": member.name,
                        "properties": member.properties,
                        "parent_group": node.name
                    })

                    result["objects"].append(
                        member.name
                    )

                    self._consume_network_object(
                        member,
                        result
                    )

                    continue

                if member.type == "ObjectGroup":

                    self._resolve_reference(
                        value=member.name,
                        context=context,
                        depth=depth + 1,
                        max_depth=max_depth,
                        visited=visited,
                        result=result
                    )


    def _find_candidates(
        self,
        value,
        context
    ):

        matches = []

        #
        # When context is known it is an isolation boundary.
        # Never resolve an object/group from another context.
        #
        if context:

            qualified = f"{context}:{value}"

            #
            # Caller may already have supplied a qualified name.
            #
            if value.startswith(f"{context}:"):
                qualified = value

            for node_type in [
                "NetworkObject",
                "ObjectGroup"
            ]:

                node = self.graph.find(
                    node_type,
                    qualified
                )

                if node:
                    matches.append(node)

            #
            # Context was explicitly supplied.
            # Do NOT fall back to objects from other contexts.
            #
            return matches

        #
        # No context supplied.
        #
        # Exact graph name first.
        #
        for node_type in [
            "NetworkObject",
            "ObjectGroup"
        ]:

            node = self.graph.find(
                node_type,
                value
            )

            if (
                node
                and node not in matches
            ):
                matches.append(node)

        #
        # Unqualified suffix search is allowed only
        # when the caller did not provide a context.
        #
        suffix = f":{value}"

        for node in self.graph.nodes.values():

            if node.type not in [
                "NetworkObject",
                "ObjectGroup"
            ]:
                continue

            if not node.name.endswith(
                suffix
            ):
                continue

            if node not in matches:
                matches.append(node)

        return matches

    def _consume_network_object(
        self,
        node,
        result
    ):

        properties = node.properties or {}

        value = (
            properties.get("value")
            or properties.get("ip")
            or node.name
        )

        parsed = self._parse_address(
            value
        )

        if not parsed:
            result["unresolved"].append(
                str(value)
            )
            return

        if parsed["type"] == "host":

            result["hosts"].append(
                parsed["value"]
            )

        else:

            result["networks"].append(
                parsed["value"]
            )


    def _parse_address(
        self,
        value
    ):

        if value is None:
            return None

        value = str(value).strip()

        #
        # CIDR network or host.
        #
        try:

            if "/" in value:

                network = ipaddress.ip_network(
                    value,
                    strict=False
                )

                if network.prefixlen == network.max_prefixlen:

                    return {
                        "type": "host",
                        "value": str(
                            network.network_address
                        )
                    }

                return {
                    "type": "network",
                    "value": str(network)
                }

        except ValueError:
            pass

        #
        # Plain IP.
        #
        try:

            ip = ipaddress.ip_address(
                value
            )

            return {
                "type": "host",
                "value": str(ip)
            }

        except ValueError:
            pass

        #
        # ASA raw network form:
        #
        # 10.84.15.0 255.255.255.240
        #
        parts = value.split()

        if len(parts) == 2:

            try:

                network = ipaddress.ip_network(
                    f"{parts[0]}/{parts[1]}",
                    strict=False
                )

                if network.prefixlen == network.max_prefixlen:

                    return {
                        "type": "host",
                        "value": str(
                            network.network_address
                        )
                    }

                return {
                    "type": "network",
                    "value": str(network)
                }

            except ValueError:
                pass

        return None


    def _ip_sort_key(
        self,
        value
    ):

        ip = ipaddress.ip_address(
            value
        )

        return (
            ip.version,
            int(ip)
        )


    def _network_sort_key(
        self,
        value
    ):

        network = ipaddress.ip_network(
            value,
            strict=False
        )

        return (
            network.version,
            int(network.network_address),
            network.prefixlen
        )