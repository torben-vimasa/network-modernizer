import ipaddress


class PathEngine:
    def __init__(self, graph):
        self.graph = graph

    def explain_ip(self, source_ip, destination_ip):
        source_matches = self._find_interfaces_for_ip(source_ip)
        destination_matches = self._find_interfaces_for_ip(destination_ip)

        print()
        print("=" * 60)
        print("PATH EXPLAIN")
        print("=" * 60)
        print(f"Source:      {source_ip}")
        print(f"Destination: {destination_ip}")

        print("\nSource candidates")
        print("-" * 20)
        self._print_matches(source_matches)

        print("\nDestination candidates")
        print("-" * 20)
        self._print_matches(destination_matches)

        print("\nInterpretation")
        print("-" * 20)

        if not source_matches:
            print("Source IP blev ikke matchet til kendt ASA/router subnet endnu.")

        if not destination_matches:
            print("Destination IP blev ikke matchet til kendt ASA/router subnet endnu.")

        if source_matches and destination_matches:
            for src in source_matches:
                for dst in destination_matches:
                    print()
                    print(f"{source_ip} kan være i/ved {src['node'].name}")
                    print(f"{destination_ip} kan være i/ved {dst['node'].name}")

                    if src["vrf"] and dst["vrf"]:
                        print(f"Source VRF:      {src['vrf']}")
                        print(f"Destination VRF: {dst['vrf']}")

                        if src["vrf"] == dst["vrf"]:
                            print("Foreløbig vurdering: samme VRF.")
                        else:
                            print("Foreløbig vurdering: kryds-VRF trafik — firewall/route/VPN/NAT skal undersøges.")

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