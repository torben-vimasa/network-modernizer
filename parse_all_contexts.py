import json
from pathlib import Path

contexts_dir = Path("data/contexts")
output_dir = Path("output")

output_dir.mkdir(exist_ok=True)

context_files = list(contexts_dir.glob("*.txt"))

all_contexts = []
as_is_interfaces = []

print(f"Contexts fundet: {len(context_files)}")

for context_file in context_files:
    context_name = context_file.stem

    with open(context_file, "r", encoding="utf-8", errors="ignore") as f:
        lines = f.readlines()

    access_list_count = 0
    object_count = 0
    acl_counts = {}
    interfaces = []
    access_groups = []
    current_interface = None

    for line in lines:
        line = line.strip()

        if line.startswith("interface "):
            current_interface = {
                "context": context_name,
                "physical_interface": line.replace("interface ", ""),
                "asa_interface": None,
                "security_level": None,
                "ip_address": None,
                "subnet_mask": None,
                "standby_ip": None,
                "shutdown": False
            }

        elif current_interface and line == "shutdown":
            current_interface["shutdown"] = True

        elif current_interface and line.startswith("nameif "):
            current_interface["asa_interface"] = line.replace("nameif ", "")

        elif current_interface and line.startswith("security-level "):
            current_interface["security_level"] = line.replace("security-level ", "")

        elif current_interface and line.startswith("ip address "):
            parts = line.split()

            if len(parts) >= 4:
                current_interface["ip_address"] = parts[2]
                current_interface["subnet_mask"] = parts[3]

            if "standby" in parts:
                standby_index = parts.index("standby")
                if len(parts) > standby_index + 1:
                    current_interface["standby_ip"] = parts[standby_index + 1]

            interfaces.append(current_interface)
            current_interface = None

        if line.startswith("access-group "):
            parts = line.split()

            if len(parts) >= 5:
                access_groups.append({
                    "acl": parts[1],
                    "direction": parts[2],
                    "asa_interface": parts[4]
                })

        if line.startswith("access-list "):
            access_list_count += 1
            parts = line.split()

            if len(parts) > 1:
                acl_name = parts[1]
                acl_counts[acl_name] = acl_counts.get(acl_name, 0) + 1

        if line.startswith("object network"):
            object_count += 1

    interface_to_acl = {
        ag["asa_interface"]: ag["acl"]
        for ag in access_groups
    }

    for interface in interfaces:
        interface["access_group"] = interface_to_acl.get(interface["asa_interface"], None)
        interface["external_vrf"] = "unknown"
        as_is_interfaces.append(interface)

    context_summary = {
        "context": context_name,
        "access_lists": access_list_count,
        "objects": object_count,
        "interfaces": len(interfaces),
        "access_groups": len(access_groups),
        "acl_count": len(acl_counts)
    }

    all_contexts.append(context_summary)

    print(
        f"{context_name}: "
        f"{access_list_count} ACLs, "
        f"{object_count} objects, "
        f"{len(interfaces)} interfaces, "
        f"{len(access_groups)} access-groups"
    )

with open(output_dir / "all_contexts_summary.json", "w") as f:
    json.dump(all_contexts, f, indent=4)

with open(output_dir / "as_is_interfaces.json", "w") as f:
    json.dump(as_is_interfaces, f, indent=4)

print("\nOutput gemt:")
print("output/all_contexts_summary.json")
print("output/as_is_interfaces.json")
print(f"AS-IS interfaces: {len(as_is_interfaces)}")