from models.router_interface import RouterInterface


class RouterInterfaceParser:

    def parse(self, lines, device="UnknownRouter"):

        interfaces = []
        current = None

        for raw_line in lines:
            stripped = raw_line.strip()

            if stripped.startswith("interface "):
                if current:
                    interfaces.append(current)

                current = RouterInterface(
                    device=device,
                    interface=stripped.split(maxsplit=1)[1],
                    vrf=None
                )
                continue

            if not current:
                continue

            if stripped.startswith("ip address "):
                parts = stripped.split()

                if len(parts) >= 3:
                    ip_part = parts[2]

                    if "/" in ip_part:
                        current.ip = ip_part.split("/")[0]
                        current.mask = ip_part.split("/")[1]
                    else:
                        current.ip = ip_part
                        if len(parts) >= 4:
                            current.mask = parts[3]

            elif stripped.startswith("ip "):
                parts = stripped.split()

                if len(parts) == 2 and parts[1].count(".") == 3:
                    current.hsrp_virtual_ip = parts[1]

            elif stripped.startswith("vrf member "):
                current.vrf = stripped.split(maxsplit=2)[2]

            elif stripped.startswith("vrf "):
                parts = stripped.split()

                if len(parts) >= 2 and parts[1] not in ["context", "definition"]:
                    current.vrf = parts[1]

        if current:
            interfaces.append(current)

        return interfaces