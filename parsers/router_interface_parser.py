from models.router_interface import RouterInterface


class RouterInterfaceParser:

    def parse(self, lines, device="UnknownRouter"):

        interfaces = []
        current = None

        for raw_line in lines:

            line = raw_line.rstrip()
            stripped = line.strip()

            #
            # New interface
            #
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

            #
            # Interface IP
            #
            if stripped.startswith("ip address "):

                parts = stripped.split()

                if len(parts) >= 3:
                    current.ip = parts[2].split("/")[0]

            #
            # HSRP VIP
            #
            elif stripped.startswith("ip "):

                parts = stripped.split()

                #
                # Avoid matching "ip address"
                #
                if (
                    len(parts) == 2
                    and parts[1].count(".") == 3
                ):
                    current.hsrp_virtual_ip = parts[1]

            #
            # NX-OS style
            #
            elif stripped.startswith("vrf member "):

                current.vrf = stripped.split(maxsplit=2)[2]

            #
            # IOS-XR style
            #
            elif stripped.startswith("vrf "):

                parts = stripped.split()

                if (
                    len(parts) >= 2
                    and parts[1] not in [
                        "context",
                        "definition"
                    ]
                ):
                    current.vrf = parts[1]

        #
        # Last interface
        #
        if current:
            interfaces.append(current)

        return interfaces