class InterfaceBuilder:

    def __init__(self, graph):
        self.graph = graph

    def add_interfaces(self, interfaces):

        for interface in interfaces:

            router_node = self.graph.add_node(
                "Router",
                interface.device
            )

            interface_node = self.graph.add_node(
                "Interface",
                f"{interface.device}:{interface.name}",
                {
                    "device": interface.device,
                    "name": interface.name,
                    "ip": interface.ip,
                    "subnet": interface.subnet,
                    "vrf": interface.vrf,
                    "interface_type": interface.interface_type,
                    "raw": interface.raw
                }
            )

            self.graph.add_relationship(
                router_node,
                interface_node,
                "HAS_INTERFACE"
            )

            if interface.ip:

                ip_node = self.graph.add_node(
                    "IPAddress",
                    interface.ip
                )

                self.graph.add_relationship(
                    interface_node,
                    ip_node,
                    "HAS_IP"
                )