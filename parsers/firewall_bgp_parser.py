from models.bgp_neighbor import BGPNeighbor


class FirewallBGPParser:

    def parse(self, lines):

        hostname = "UnknownFirewall"
        local_as = None
        neighbors = {}

        in_bgp = False

        for raw_line in lines:
            line = raw_line.strip()

            if line.startswith("hostname "):
                hostname = line.split(maxsplit=1)[1]
                continue

            if line.startswith("router bgp "):
                in_bgp = True
                try:
                    local_as = int(line.split()[2])
                except ValueError:
                    local_as = None
                continue

            if not in_bgp:
                continue

            if line.startswith("!") and in_bgp:
                continue

            if not line.startswith("neighbor "):
                continue

            parts = line.split()

            if len(parts) < 3:
                continue

            peer = parts[1]
            command = parts[2]

            neighbor = neighbors.setdefault(
                peer,
                BGPNeighbor(
                    device=hostname,
                    local_as=local_as,
                    neighbor=peer
                )
            )

            if command == "remote-as" and len(parts) >= 4:
                try:
                    neighbor.remote_as = int(parts[3])
                except ValueError:
                    neighbor.remote_as = None

            elif command == "description" and len(parts) >= 4:
                neighbor.description = " ".join(parts[3:])

            elif command == "activate":
                neighbor.activated = True

            elif command == "next-hop-self":
                neighbor.next_hop_self = True

            elif command == "prefix-list" and len(parts) >= 5:
                direction = parts[4]
                if direction == "in":
                    neighbor.prefix_list_in = parts[3]
                elif direction == "out":
                    neighbor.prefix_list_out = parts[3]

            elif command == "route-map" and len(parts) >= 5:
                direction = parts[4]
                if direction == "in":
                    neighbor.route_map_in = parts[3]
                elif direction == "out":
                    neighbor.route_map_out = parts[3]

        return list(neighbors.values())