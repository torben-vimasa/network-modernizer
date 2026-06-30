from parsers.interface_parser import InterfaceParser


sample = [
    "interface TenGigE0/0/0/10",
    " description Transit to BHASA",
    " ip address 172.21.2.26/28",
    "!",
    "interface Loopback0",
    " ip address 172.17.91.208/32",
]

interfaces = InterfaceParser().parse(
    sample,
    device="OBvDCPe1"
)

print()
print("Interface Parser")
print("=" * 60)

for interface in interfaces:
    print(interface)