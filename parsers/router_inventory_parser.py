import ipaddress

from models.router import Router
from models.interface import Interface


class RouterInventoryParser:

    def parse(self, router_name, lines):

        router = Router(name=router_name)

        current_interface = None
        current_vrf = "default"

        for raw in lines:

            line = raw.rstrip()

            #
            # Interface
            #
            if line.startswith("interface "):

                if current_interface:
                    router.interfaces.append(
                        current_interface
                    )

                current_interface = Interface(
                    name=line.split()[1],
                    vrf="default",
                    ip=None,
                    prefix=None,
                    description=None
                )

                current_vrf = "default"
                continue

            if not current_interface:
                continue

            stripped = line.strip()

            #
            # Description
            #
            if stripped.startswith("description "):

                current_interface.description = (
                    stripped.replace(
                        "description ",
                        "",
                        1
                    )
                )

                continue

            #
            # VRF
            #
            if stripped.startswith("vrf member "):

                current_vrf = stripped.replace(
                    "vrf member ",
                    "",
                    1
                )

                current_interface.vrf = current_vrf
                continue

            if stripped.startswith("vrf forwarding "):

                current_vrf = stripped.replace(
                    "vrf forwarding ",
                    "",
                    1
                )

                current_interface.vrf = current_vrf
                continue

            if stripped.startswith("vrf "):

                current_vrf = stripped.replace(
                    "vrf ",
                    "",
                    1
                )

                current_interface.vrf = current_vrf
                continue

            #
            # IOS / IOS-XE / NX-OS
            #
            # ip address 10.1.1.1/24
            # ip address 10.1.1.1 255.255.255.0
            #
            if stripped.startswith("ip address "):

                tokens = stripped.split()

                self._set_ipv4_address(
                    current_interface,
                    tokens[2:]
                )

                continue

            #
            # IOS-XR
            #
            # ipv4 address 172.17.91.208 255.255.255.255
            #
            if stripped.startswith("ipv4 address "):

                tokens = stripped.split()

                self._set_ipv4_address(
                    current_interface,
                    tokens[2:]
                )

                continue

        #
        # Last interface
        #
        if current_interface:
            router.interfaces.append(
                current_interface
            )

        return router


    def _set_ipv4_address(
        self,
        interface,
        address_tokens
    ):

        if not address_tokens:
            return

        address = address_tokens[0]

        try:

            #
            # CIDR notation
            #
            if "/" in address:

                parsed = ipaddress.ip_interface(
                    address
                )

            #
            # Address + dotted mask
            #
            elif len(address_tokens) >= 2:

                parsed = ipaddress.ip_interface(
                    f"{address}/"
                    f"{address_tokens[1]}"
                )

            else:
                return

        except ValueError:
            return

        interface.ip = str(
            parsed.ip
        )

        interface.prefix = str(
            parsed.network
        )