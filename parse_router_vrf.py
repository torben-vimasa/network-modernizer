import json
import re
from pathlib import Path

router_raw_dir = Path("data/router_raw")
output_dir = Path("output")
output_dir.mkdir(exist_ok=True)

router_files = list(router_raw_dir.glob("*.txt"))

router_interfaces = []


def should_keep_interface(interface):
    if interface["vrf"] != "default":
        return True

    if interface["ip_address"]:
        return True

    if interface["description"]:
        return True

    return False


for router_file in router_files:
    router_name = router_file.stem

    with open(router_file, "r", encoding="utf-8", errors="ignore") as f:
        lines = f.readlines()

    current_interface = None

    for raw_line in lines:
        line = raw_line.strip()

        line = re.sub(r"\x1b\[[0-9;]*[A-Za-z]", "", line)
        line = line.replace("--More--", "").strip()

        if not line:
            continue

        if line.startswith("hostname "):
            router_name = line.replace("hostname ", "").strip()

        if line.startswith("interface "):
            if current_interface and should_keep_interface(current_interface):
                router_interfaces.append(current_interface)

            current_interface = {
                "router": router_name,
                "interface": line.replace("interface ", ""),
                "description": None,
                "vrf": "default",
                "ip_address": None,
                "shutdown": False
            }

        elif current_interface and line.startswith("description "):
            current_interface["description"] = line.replace("description ", "")

        elif current_interface and line.startswith("vrf member "):
            vrf = line.replace("vrf member ", "").strip()

            if vrf:
                current_interface["vrf"] = vrf

        elif current_interface and line.startswith("ip address "):
            current_interface["ip_address"] = line.replace("ip address ", "")

        elif current_interface and line == "shutdown":
            current_interface["shutdown"] = True

    if current_interface and should_keep_interface(current_interface):
        router_interfaces.append(current_interface)


with open(output_dir / "router_vrf_interfaces.json", "w") as f:
    json.dump(router_interfaces, f, indent=4)

vrf_summary = {}

for interface in router_interfaces:
    vrf = interface["vrf"]

    if vrf not in vrf_summary:
        vrf_summary[vrf] = {
            "interfaces": 0,
            "routers": set(),
            "interface_list": []
        }

    vrf_summary[vrf]["interfaces"] += 1
    vrf_summary[vrf]["routers"].add(interface["router"])

    vrf_summary[vrf]["interface_list"].append({
        "router": interface["router"],
        "interface": interface["interface"],
        "description": interface["description"],
        "ip_address": interface["ip_address"],
        "shutdown": interface["shutdown"]
    })

for vrf in vrf_summary:
    vrf_summary[vrf]["routers"] = list(vrf_summary[vrf]["routers"])

with open(output_dir / "vrf_summary.json", "w") as f:
    json.dump(vrf_summary, f, indent=4)

print("Router VRF interface analyse")
print("----------------------------")
print(f"Router files: {len(router_files)}")
print(f"Interfaces fundet: {len(router_interfaces)}")
print("Output gemt: output/router_vrf_interfaces.json")
print("Output gemt: output/vrf_summary.json")
print(f"VRFs fundet: {len(vrf_summary)}")