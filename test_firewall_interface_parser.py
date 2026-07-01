from pathlib import Path

from parsers.firewall_interface_parser import FirewallInterfaceParser


files = [
    Path("data/firewalls/RGDC-CAT3-FW1-1.txt"),
    Path("data/firewalls/OBV-CAT3-FW1-1.txt"),
]

parser = FirewallInterfaceParser()

for file in files:
    print()
    print("Firewall Interface Parser")
    print("=" * 60)
    print("File:", file)

    with open(file, encoding="utf-8", errors="ignore") as f:
        interfaces = parser.parse(f.readlines())

    routed = [i for i in interfaces if i.nameif and i.ip]

    print("Interfaces:", len(interfaces))
    print("Routed    :", len(routed))

    for interface in routed[:10]:
        print()
        print("Device     :", interface.device)
        print("Interface  :", interface.interface)
        print("Nameif     :", interface.nameif)
        print("VLAN       :", interface.vlan)
        print("IP         :", interface.ip)
        print("Mask       :", interface.mask)
        print("Description:", interface.description)