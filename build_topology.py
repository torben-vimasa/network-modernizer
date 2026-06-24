import json
import ipaddress
from pathlib import Path

output_dir = Path("output")

with open(output_dir / "as_is_interfaces.json", "r") as f:
    asa_interfaces = json.load(f)

with open(output_dir / "router_vrf_interfaces.json", "r") as f:
    router_interfaces = json.load(f)

topology_links = []

for asa in asa_interfaces:
    asa_ip = asa.get("ip_address")
    asa_mask = asa.get("subnet_mask")

    if not asa_ip or not asa_mask:
        continue

    try:
        asa_network = ipaddress.ip_network(f"{asa_ip}/{asa_mask}", strict=False)
    except ValueError:
        continue

    for router in router_interfaces:
        router_ip = router.get("ip_address")

        if not router_ip:
            continue

        try:
            router_interface = ipaddress.ip_interface(router_ip)
        except ValueError:
            continue

        if router_interface.ip in asa_network:
            topology_links.append({
                "asa_context": asa["context"],
                "asa_interface": asa["asa_interface"],
                "asa_physical_interface": asa["physical_interface"],
                "asa_ip": asa_ip,
                "asa_subnet": str(asa_network),
                "asa_access_group": asa.get("access_group"),
                "router": router["router"],
                "router_interface": router["interface"],
                "router_description": router["description"],
                "router_ip": router_ip,
                "vrf": router["vrf"]
            })

with open(output_dir / "asa_router_topology.json", "w") as f:
    json.dump(topology_links, f, indent=4)

print("ASA ↔ Router topology")
print("---------------------")
print(f"Matches fundet: {len(topology_links)}")
print("Output gemt: output/asa_router_topology.json")
vrf_topology = {}

for link in topology_links:
    vrf = link["vrf"]

    if vrf not in vrf_topology:
        vrf_topology[vrf] = []

    vrf_topology[vrf].append({
        "asa_context": link["asa_context"],
        "asa_interface": link["asa_interface"],
        "asa_ip": link["asa_ip"],
        "asa_subnet": link["asa_subnet"],
        "asa_access_group": link["asa_access_group"],
        "router": link["router"],
        "router_interface": link["router_interface"],
        "router_ip": link["router_ip"]
    })

with open(output_dir / "vrf_asa_topology.json", "w") as f:
    json.dump(vrf_topology, f, indent=4)

print("Output gemt: output/vrf_asa_topology.json")
print(f"VRFs med ASA-links: {len(vrf_topology)}")
vrf_inventory = {}

for vrf, links in vrf_topology.items():
    contexts = set()
    asa_interfaces = set()
    access_groups = set()
    routers = set()
    router_interfaces = set()

    for link in links:
        contexts.add(link["asa_context"])
        asa_interfaces.add(link["asa_interface"])
        routers.add(link["router"])
        router_interfaces.add(link["router_interface"])

        if link["asa_access_group"]:
            access_groups.add(link["asa_access_group"])

    vrf_inventory[vrf] = {
        "contexts": sorted(list(contexts)),
        "asa_interfaces": sorted(list(asa_interfaces)),
        "access_groups": sorted(list(access_groups)),
        "routers": sorted(list(routers)),
        "router_interfaces": sorted(list(router_interfaces)),
        "link_count": len(links),
        "complexity_score": (
    len(contexts) * 3
    + len(asa_interfaces) * 2
    + len(access_groups) * 2
    + len(router_interfaces)
      )
    }

with open(output_dir / "vrf_inventory.json", "w") as f:
    json.dump(vrf_inventory, f, indent=4)

print("Output gemt: output/vrf_inventory.json")
print(f"VRF inventory entries: {len(vrf_inventory)}")
for link in topology_links[:20]:
    print(
        f'{link["asa_context"]} / {link["asa_interface"]} '
        f'→ {link["router"]} / {link["router_interface"]} '
        f'→ VRF {link["vrf"]}'
    )
    vrf_ranking = sorted(
    vrf_inventory.items(),
    key=lambda x: x[1]["complexity_score"],
    reverse=True
)

with open(output_dir / "vrf_complexity_ranking.json", "w") as f:
    json.dump(vrf_ranking, f, indent=4)

print("Output gemt: output/vrf_complexity_ranking.json")