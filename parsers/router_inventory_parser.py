import ipaddress

from models.router import Router
from models.interface import Interface


class RouterInventoryParser:

    def parse(self, router_name, lines):

        router = Router(name=router_name)

        current_interface = None
        current_vrf = "default"
        in_hsrp = False

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
                in_hsrp = False
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
            # NX-OS:
            #   vrf member MGMT
            #
            # IOS / IOS-XE:
            #   ip vrf forwarding MGMT
            #   vrf forwarding MGMT
            #
            # IOS-XR / generic:
            #   vrf MGMT
            #
            if stripped.startswith("vrf member "):

                current_vrf = stripped.replace(
                    "vrf member ",
                    "",
                    1
                )

                current_interface.vrf = current_vrf
                continue

            if stripped.startswith("ip vrf forwarding "):

                current_vrf = stripped.replace(
                    "ip vrf forwarding ",
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
            # HSRP configuration.
            #
            # NX-OS:
            #
            #   hsrp 2
            #     priority 210
            #     ip 172.27.2.1
            #
            # IOS-XR:
            #
            #   hsrp 2
            #     priority 240
            #     address 172.27.2.1
            #
            if stripped.startswith("hsrp "):

                tokens = stripped.split()

                if (
                    len(tokens) >= 2
                    and tokens[1].isdigit()
                ):
                    in_hsrp = True
                else:
                    in_hsrp = False

                continue

            if in_hsrp:

                if stripped.startswith("priority "):

                    tokens = stripped.split()

                    if len(tokens) >= 2:

                        try:
                            current_interface.hsrp_priority = int(
                                tokens[1]
                            )

                        except ValueError:
                            pass

                    continue

                if stripped.startswith("ip "):

                    tokens = stripped.split()

                    if (
                        len(tokens) >= 2
                        and self._is_ipv4(tokens[1])
                    ):
                        current_interface.hsrp_virtual_ip = (
                            tokens[1]
                        )

                    continue

                if stripped.startswith("address "):

                    tokens = stripped.split()

                    if (
                        len(tokens) >= 2
                        and self._is_ipv4(tokens[1])
                    ):
                        current_interface.hsrp_virtual_ip = (
                            tokens[1]
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


    def _is_ipv4(self, value):

        try:
            ipaddress.IPv4Address(value)
            return True

        except ValueError:
            return False
