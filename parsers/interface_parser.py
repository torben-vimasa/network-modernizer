import re

from models.network_interface import NetworkInterface


class InterfaceParser:

    IP_ADDRESS = re.compile(
        r"^\s*ip address\s+(\d+\.\d+\.\d+\.\d+)/(\d+)"
    )

    def parse(self, lines, device=None):

        interfaces = []
        current = None

        for raw_line in lines:
            line = raw_line.rstrip()

            if line.startswith("interface "):

                if current:
                    interfaces.append(current)

                current = NetworkInterface(
                    device=device,
                    name=line.replace("interface ", "").strip(),
                    interface_type="router",
                    raw=line
                )

                continue

            if not current:
                continue

            ip_match = self.IP_ADDRESS.match(line)

            if ip_match:
                ip = ip_match.group(1)
                prefix = ip_match.group(2)

                current.ip = ip
                current.subnet = f"{ip}/{prefix}"

        if current:
            interfaces.append(current)

        return interfaces