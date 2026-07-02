from builders.router_interface_export_builder import RouterInterfaceExportBuilder


interfaces = RouterInterfaceExportBuilder().build()

print()
print("Router Interface Export Builder")
print("=" * 60)
print("Interfaces:", len(interfaces))
print("Output    : output/router_interfaces.json")

for i in interfaces:
    if i.interface in ["Vlan3100", "Vlan3101", "Vlan3102"]:
        print()
        print("Device :", i.device)
        print("Intf   :", i.interface)
        print("IP     :", i.ip)
        print("HSRP   :", i.hsrp_virtual_ip)