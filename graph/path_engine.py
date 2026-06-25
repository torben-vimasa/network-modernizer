import ipaddress

from models.path_result import PathResult


class PathEngine:
    def __init__(self, graph):
        self.graph = graph

    def analyze_ip_path(self, source_ip, destination_ip):
        source_matches = self._find_interfaces_for_ip(source_ip)
        destination_matches = self._find_interfaces_for_ip(destination_ip)

        result = PathResult(
            source_ip=source_ip,
            destination_ip=destination_ip
        )

        result.source_matches = source_matches
        result.destination_matches = destination_matches

        self._add_summary(result)
        self._add_findings(result)

        return result

    def explain_ip(self, source_ip, destination_ip):
        result = self.analyze_ip_path(source_ip, destination_ip)

        print()
        print("=" * 60)
        print("PATH EXPLAIN")
        print("=" * 60)
        print(f"Source:      {result.source_ip}")
        print(f"Destination: {result.destination_ip}")

        print("\nSource candidates")
        print("-" * 20)
        self._print_matches(result.source_matches)

        print("\nDestination candidates")
        print("-" * 20)
        self._print_matches(result.destination_matches)

        print("\nFindings")
        print("-" * 20)

        for finding in result.findings:
            print(f"- {finding}")

        if result.warnings:
            print("\nWarnings")
            print("-" * 20)

            for warning in result.warnings:
                print(f"- {warning}")

        print("\nSummary")
        print("-" * 20)
        print(f"VRFs:       {result.vrfs}")
        print(f"Firewalls:  {result.firewalls}")
        print(f"Routers:    {result.routers}")
        print(f"Confidence: {result.confidence}")

    def _add_summary(self, result):
        vrfs = set()
        firewalls = set()
        routers = set()

        for match in result.source_matches + result.destination_matches:
            node = match["node"]

            if match["vrf"]:
                vrfs.add(match["vrf"])

            if node.type == "ASAInterface":
                context = node.properties.get("context")
                if context:
                    firewalls.add(context)

            if node.type == "RouterInterface":
                router = node.properties.get("router")
                if router:
                    routers.add(router)

        result.vrfs = sorted(list(vrfs))
        result.firewalls = sorted(list(firewalls))
        result.routers = sorted(list(routers))

    def _add_findings(self, result):
        if not result.source_matches:
            result.warnings.append(
                "Source IP blev ikke matchet til kendt ASA/router subnet endnu."
            )

        if not result.destination_matches:
            result.warnings.append(
                "Destination IP blev ikke matchet til kendt ASA/router subnet endnu."
            )

        if result.source_matches and result.destination_matches:
            source_vrfs = {
                match["vrf"]
                for match in result.source_matches
                if match["vrf"]
            }

            destination_vrfs = {
                match["vrf"]
                for match in result.destination_matches
                if match["vrf"]
            }

            if source_vrfs and destination_vrfs:
                if source_vrfs == destination_vrfs:
                    result.findings.append("Source og destination ser ud til at være i samme VRF.")
                    result.confidence = 60
                else:
                    result.findings.append(
                        "Source og destination ser ud til at være i forskellige VRF'er."
                    )
                    result.findings.append(
                        "Kryds-VRF trafik kræver videre analyse af firewall, routes, NAT og/eller VPN."
                    )
                    result.confidence = 50
            else:
                result.findings.append(
                    "VRF kunne ikke bestemmes entydigt for source eller destination."
                )
                result.confidence = 30

    def _find_interfaces_for_ip(self, ip):
        matches = []
        ip_obj = ipaddress.ip_address(ip)

        for node in self.graph.nodes.values():
            if node.type not in ["ASAInterface", "RouterInterface"]:
                continue

            subnet = node.properties.get("subnet")
            interface_ip = node.properties.get("ip")
            network = None

            if subnet:
                try:
                    network = ipaddress.ip_network(subnet, strict=False)
                except ValueError:
                    pass

            elif interface_ip:
                try:
                    network = ipaddress.ip_interface(interface_ip).network
                except ValueError:
                    pass

            if network and ip_obj in network:
                vrf = self._find_connected_vrf(node.id)

                matches.append({
                    "node": node,
                    "network": str(network),
                    "vrf": vrf
                })

        return matches

    def _find_connected_vrf(self, node_id):
        for relation, neighbor in self.graph.neighbors(node_id):
            if neighbor.type == "VRF":
                return neighbor.name

        return None

    def _print_matches(self, matches):
        if not matches:
            print("Ingen match fundet.")
            return

        for match in matches:
            node = match["node"]
            print(
                f'{node.type:16} {node.name:35} '
                f'network={match["network"]:18} '
                f'vrf={match["vrf"]}'
            )