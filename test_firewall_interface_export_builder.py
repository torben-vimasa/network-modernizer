from builders.firewall_interface_export_builder import FirewallInterfaceExportBuilder

interfaces = FirewallInterfaceExportBuilder().build()

print()
print("Firewall Interface Export Builder")
print("=" * 60)
print("Interfaces:", len(interfaces))
print("Output: output/firewall_interfaces.json")

for i in interfaces:
    if (
        i.nameif == "STTN_MGMT"
        or i.ip == "172.21.2.49"
        or i.interface == "Port-channel4.729"
    ):
        print("MATCH:", i)