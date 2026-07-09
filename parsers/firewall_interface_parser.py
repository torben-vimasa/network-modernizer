from models.firewall_interface import FirewallInterface


class FirewallInterfaceParser:

    def parse(self, lines, device=None, context=None):

        hostname = None
        interfaces = []
        current = None

        for raw_line in lines:
            stripped = raw_line.strip()

            if stripped.startswith("hostname "):
                hostname = stripped.split(maxsplit=1)[1]
                continue

            if stripped.startswith("interface "):
                if current:
                    interfaces.append(current)

                current = FirewallInterface(
                    device=device or hostname or context or "UnknownFirewall",
                    context=context or hostname or device or "UnknownFirewall",
                    interface=stripped.split(maxsplit=1)[1]
                )
                continue

            if not current:
                continue

            if stripped.startswith("description "):
                current.description = stripped.split(maxsplit=1)[1]

            elif stripped.startswith("vlan "):
                try:
                    current.vlan = int(stripped.split()[1])
                except ValueError:
                    current.vlan = None

            elif stripped.startswith("nameif "):
                current.nameif = stripped.split(maxsplit=1)[1]

            elif stripped.startswith("security-level "):
                try:
                    current.security_level = int(stripped.split()[1])
                except ValueError:
                    current.security_level = None

            elif stripped.startswith("ip address "):
                parts = stripped.split()

                if len(parts) >= 4:
                    current.ip = parts[2]
                    current.mask = parts[3]

                if "standby" in parts:
                    idx = parts.index("standby")
                    if len(parts) > idx + 1:
                        current.standby_ip = parts[idx + 1]

        if current:
            interfaces.append(current)

        return interfaces