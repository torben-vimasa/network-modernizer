from models.router_interface import RouterInterface


class RouterInterfaceParser:

    def parse(self, lines, device="UnknownRouter"):

        interfaces = []
        current = None

        for raw_line in lines:
            line = raw_line.rstrip()
            stripped = line.strip()

            if stripped.startswith("interface "):
                if current:
                    interfaces.append(current)

                current = RouterInterface(
                    device=device,
                    interface=stripped.split(maxsplit=1)[1]
                )
                continue

            if not current:
                continue

            if stripped.startswith("ip address "):
                parts = stripped.split()
                if len(parts) >= 3:
                    current.ip = parts[2].split("/")[0]

            elif stripped.startswith("ip "):
                parts = stripped.split()
                if len(parts) >= 2:
                    current.hsrp_virtual_ip = parts[1]

        if current:
            interfaces.append(current)

        return interfaces