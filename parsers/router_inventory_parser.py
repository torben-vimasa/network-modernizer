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
                    router.interfaces.append(current_interface)

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

                current_interface.description = stripped.replace(
                    "description ",
                    "",
                    1
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

            if stripped.startswith("vrf "):

                current_vrf = stripped.replace(
                    "vrf ",
                    "",
                    1
                )

                current_interface.vrf = current_vrf
                continue

            #
            # IP
            #
            if stripped.startswith("ip address "):

                tokens = stripped.split()

                #
                # ip address 10.1.1.1/24
                #
                if "/" in tokens[2]:

                    interface = ipaddress.ip_interface(tokens[2])

                    current_interface.ip = str(interface.ip)
                    current_interface.prefix = str(interface.network)

                #
                # ip address 10.1.1.1 255.255.255.0
                #
                elif len(tokens) >= 4:

                    interface = ipaddress.ip_interface(
                        f"{tokens[2]}/{tokens[3]}"
                    )

                    current_interface.ip = str(interface.ip)
                    current_interface.prefix = str(interface.network)

        #
        # Last interface
        #
        if current_interface:
            router.interfaces.append(current_interface)

        return router