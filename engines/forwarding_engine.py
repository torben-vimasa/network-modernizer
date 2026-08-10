import ipaddress

from models.forwarding_result import ForwardingResult


class ForwardingEngine:

    def __init__(self, graph):
        self.graph = graph

    def resolve_next_hop(self, current_device, next_hop):

        #
        # Step 1
        # Exact interface IP lookup
        #
        direct = self._resolve_interface_ip(
            current_device,
            next_hop
        )

        if direct:
            return direct

        #
        # Step 2
        # Find subnet candidates
        #
        result = self.candidates_for_next_hop(
            next_hop,
            exclude_device=current_device
        )

        #
        # No subnet contains the next-hop IP
        #
        if not result["subnet_found"]:
            return ForwardingResult(
                resolved=False,
                method="unknown",
                reason=f"No subnet found for {next_hop}"
            )

        #
        # Subnet exists, but no managed device owns the next-hop.
        # This usually indicates a provider-managed CPE/PE router.
        #
        if not result["found"]:
            print(
                f"DEBUG INVENTORY BOUNDARY: "
                f"device={current_device}, "
                f"next_hop={next_hop}, "
                f"subnet={result['subnet']}"
            )
            return ForwardingResult(
                resolved=False,
                method="inventory_boundary",
                inventory_boundary=True,
                reason=(
                    f"Next-hop {next_hop} belongs to subnet "
                    f"{result['subnet']}, but no managed device "
                    f"owns the next-hop address."
                )
         )
        #
        # Step 3
        # HSRP lookup
        #
        hsrp_matches = []

        for candidate in result["candidates"]:

            if candidate.get("hsrp_virtual_ip") == next_hop:
                hsrp_matches.append(candidate)

        active_matches = [
            c for c in hsrp_matches
            if c.get("hsrp_state") == "Active"
        ]

        if len(active_matches) == 1:
            candidate = active_matches[0]

            return ForwardingResult(
                resolved=True,
                method="hsrp_active",
                device=candidate["device"],
                device_type=candidate["device_type"],
                interface=candidate["interface"],
                reason=(
                    f"Next-hop {next_hop} matches active HSRP VIP "
                    f"{candidate['interface']}"
                )
            )

        priority_matches = [
            candidate
            for candidate in hsrp_matches
            if candidate.get("hsrp_priority") is not None
        ]

        if priority_matches:
            highest_priority = max(
                candidate["hsrp_priority"]
                for candidate in priority_matches
            )

            highest_matches = [
                candidate
                for candidate in priority_matches
                if candidate["hsrp_priority"] == highest_priority
            ]

            if len(highest_matches) == 1:
                candidate = highest_matches[0]

                return ForwardingResult(
                    resolved=True,
                    method="hsrp_priority",
                    device=candidate["device"],
                    device_type=candidate["device_type"],
                    interface=candidate["interface"],
                    reason=(
                        f"Next-hop {next_hop} matches HSRP VIP "
                        f"{candidate['interface']} with highest "
                        f"configured priority {highest_priority}"
                    )
                )

        if len(hsrp_matches) == 1:

            candidate = hsrp_matches[0]

            return ForwardingResult(
                resolved=True,
                method="hsrp_virtual_ip",
                device=candidate["device"],
                device_type=candidate["device_type"],
                interface=candidate["interface"],
                reason=(
                    f"Next-hop {next_hop} matches HSRP VIP "
                    f"{candidate['interface']}"
                )
            )

        if len(hsrp_matches) > 1:

            return ForwardingResult(
                resolved=False,
                method="hsrp_virtual_ip",
                reason=(
                    f"HSRP VIP {next_hop} exists on "
                    f"{len(hsrp_matches)} routers"
                ),
                candidates=hsrp_matches
            )

        return ForwardingResult(
            resolved=False,
            method="none",
            reason=f"Unable to resolve {next_hop}"
        )

    def candidates_for_next_hop(
        self,
        next_hop,
        exclude_device=None
    ):

        subnet = self._find_subnet_for_ip(next_hop)

        if not subnet:
            return {
                "subnet_found": False,
                "found": False,
                "subnet": None,
                "candidate_count": 0,
                "reason": f"No subnet found for next-hop {next_hop}",
                "candidates": []
            }

        candidates = []

        for relation, neighbor in self.graph.neighbors(subnet.id):

            if relation != "IN_SUBNET":
                continue

            if neighbor.type not in [
                "RouterInterface",
                "ASAInterface",
                "Interface"
            ]:
                continue

            device = self._find_parent_device(neighbor)

            if not device:
                continue

            if exclude_device and device.name == exclude_device:
                continue

            candidates.append(
                {
                    "device": device.name,
                    "device_type": device.type,
                    "interface": neighbor.name,
                    "interface_type": neighbor.type,
                    "subnet": subnet.name,
                    "ip": neighbor.properties.get("ip"),
                    "hsrp_virtual_ip": neighbor.properties.get("hsrp_virtual_ip"),
                    "hsrp_state": neighbor.properties.get("hsrp_state"),
                    "hsrp_priority": neighbor.properties.get("hsrp_priority"),
                    "reason": f"{neighbor.name} is in subnet {subnet.name}"
                }
            )

        return {
            "subnet_found": True,
            "found": bool(candidates),
            "subnet": subnet.name,
            "candidate_count": len(candidates),
            "candidates": candidates
        }

    def _resolve_interface_ip(
        self,
        current_device,
        next_hop
    ):

        for node in self.graph.nodes.values():

            if node.type not in [
                "RouterInterface",
                "ASAInterface",
                "Interface"
            ]:
                continue

            ip = node.properties.get("ip")

            if not ip:
                continue

            if str(ip).split("/")[0] != next_hop:
                continue

            device = self._find_parent_device(node)

            if not device:
                continue

            if current_device and device.name == current_device:
                continue

            return ForwardingResult(
                resolved=True,
                method="interface_ip",
                device=device.name,
                device_type=device.type,
                interface=node.name,
                reason=f"Next-hop {next_hop} matches interface {node.name}"
            )

        return None

    def _find_subnet_for_ip(self, ip):

        address = ipaddress.ip_address(ip)

        for node in self.graph.nodes.values():

            if node.type != "Subnet":
                continue

            prefix = node.properties.get("prefix") or node.name

            try:
                network = ipaddress.ip_network(
                    prefix,
                    strict=False
                )
            except ValueError:
                continue

            if address in network:
                return node

        return None

    def _find_parent_device(self, interface_node):

        #
        # RouterInterface
        #      |
        # HAS_INTERFACE
        #      |
        # Router
        #
        # ASAInterface
        #      |
        # HAS_INTERFACE
        #      |
        # Context
        #

        for relation, neighbor in self.graph.neighbors(interface_node.id):

            if relation != "HAS_INTERFACE":
                continue

            if neighbor.type in [
                "Router",
                "Firewall",
                "Switch",
                "Context"
            ]:
                return neighbor

        return None        