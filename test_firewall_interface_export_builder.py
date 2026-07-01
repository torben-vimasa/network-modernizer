from builders.firewall_interface_export_builder import FirewallInterfaceExportBuilder


interfaces = FirewallInterfaceExportBuilder().build()

routed = [i for i in interfaces if i.nameif and i.ip]

print()
print("Firewall Interface Export Builder")
print("=" * 60)
print("Interfaces:", len(interfaces))
print("Routed    :", len(routed))
print("Output    : output/firewall_interfaces.json")

for interface in routed[:10]:
    print()
    print("Device   :", interface.device)
    print("Nameif   :", interface.nameif)
    print("VLAN     :", interface.vlan)
    print("IP       :", interface.ip)
    print("Mask     :", interface.mask)