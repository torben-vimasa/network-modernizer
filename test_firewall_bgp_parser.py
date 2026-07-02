from pathlib import Path

from parsers.firewall_bgp_parser import FirewallBGPParser


files = [
    Path("data/firewalls/RGDC-CAT3-FW1-1.txt"),
    Path("data/firewalls/OBV-CAT3-FW1-1.txt"),
]

parser = FirewallBGPParser()

for file in files:
    with open(file, encoding="utf-8", errors="ignore") as f:
        neighbors = parser.parse(f.readlines())

    print()
    print("Firewall BGP Parser")
    print("=" * 60)
    print("File     :", file)
    print("Neighbors:", len(neighbors))

    for n in neighbors[:15]:
        print()
        print("Device      :", n.device)
        print("Local AS    :", n.local_as)
        print("Neighbor    :", n.neighbor)
        print("Remote AS   :", n.remote_as)
        print("Description :", n.description)
        print("Activated   :", n.activated)
        print("NH self     :", n.next_hop_self)
        print("PL in       :", n.prefix_list_in)
        print("PL out      :", n.prefix_list_out)
        print("RM in       :", n.route_map_in)
        print("RM out      :", n.route_map_out)