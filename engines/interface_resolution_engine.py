import ipaddress


class InterfaceResolutionEngine:

    def __init__(self, interfaces=None):
        self.interfaces = interfaces or []

    def resolve_egress(self, next_hop):

        ip = ipaddress.ip_address(next_hop)

        for interface in self.interfaces:

            subnet = interface.get("subnet")

            #
            # New normalized firewall interface format
            #
            if not subnet:

                address = interface.get("ip")
                mask = interface.get("mask")

                if address and mask:
                    subnet = str(
                        ipaddress.ip_network(
                            f"{address}/{mask}",
                            strict=False
                        )
                    )

            if not subnet:
                continue

            network = ipaddress.ip_network(
                subnet,
                strict=False
            )

            if ip in network:
                return interface

        return None