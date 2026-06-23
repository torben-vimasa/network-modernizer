import json
from pathlib import Path

config_file = Path("data/asa_config.txt")

with open(config_file, "r") as f:
    lines = f.readlines()

name_count = 0
access_list_count = 0
object_count = 0
any_any_rules = []
acl_counts = {}
rules = []
interfaces = []
current_interface = None
access_groups = []

for line in lines:
    line = line.strip()

    if line.startswith("interface "):
        current_interface = {
            "physical_interface": line.replace("interface ", ""),
            "asa_interface": None,
            "security_level": None,
            "ip_address": None,
            "subnet_mask": None,
            "standby_ip": None
        }

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

    if line.startswith("name "):
        name_count += 1

    if line.startswith("object network"):
        object_count += 1

    if line.startswith("access-list "):
        access_list_count += 1
        parts = line.split()

        if len(parts) > 1:
            acl_name = parts[1]
            acl_counts[acl_name] = acl_counts.get(acl_name, 0) + 1

            rules.append({
                "acl": acl_name,
                "rule": line
            })

        if " any any" in line:
            any_any_rules.append(line)
    if line.startswith("access-group "):
        parts = line.split()

        if len(parts) >= 5:
            access_groups.append({
                "acl": parts[1],
                "direction": parts[2],
                "asa_interface": parts[4]
            })
            acl_to_interface = {
    ag["acl"]: ag["asa_interface"]
    for ag in access_groups
}

for rule in rules:
    rule["asa_interface"] = acl_to_interface.get(rule["acl"], "unknown")
top_acls = dict(
    sorted(
        acl_counts.items(),
        key=lambda x: x[1],
        reverse=True
    )[:10]
)

report = {
    "names": name_count,
    "access_lists": access_list_count,
    "objects": object_count,
    "any_any_rules": len(any_any_rules),
    "acl_count": len(acl_counts),
    "top_acls": top_acls
}

with open("output/report.json", "w") as f:
    json.dump(report, f, indent=4)

with open("output/rules.json", "w") as f:
    json.dump(rules, f, indent=4)

print("ASA Analyse")
print("------------")
print(f"Names: {name_count}")
print(f"Access Lists: {access_list_count}")
print(f"Objects: {object_count}")
print(f"Any-Any Rules: {len(any_any_rules)}")
print(f"ACL Count: {len(acl_counts)}")

print("\nTop ACLs")
print("--------")
for acl, count in top_acls.items():
    print(f"{acl}: {count}")

print("\nOutput gemt:")
print("output/report.json")
print("output/rules.json")
largest_acl = max(acl_counts, key=acl_counts.get)

largest_acl_rules = [
    rule for rule in rules
    if rule["acl"] == largest_acl
]

with open("output/largest_acl.json", "w") as f:
    json.dump(largest_acl_rules, f, indent=4)

print(f"\nStørste ACL: {largest_acl}")
print(f"Regler: {len(largest_acl_rules)}")
service_counts = {}

for rule in largest_acl_rules:
    text = rule["rule"]

    if " permit tcp " in text:
        service_counts["tcp"] = service_counts.get("tcp", 0) + 1

    elif " permit udp " in text:
        service_counts["udp"] = service_counts.get("udp", 0) + 1

    elif " permit icmp " in text:
        service_counts["icmp"] = service_counts.get("icmp", 0) + 1

print("\nServices i største ACL")
print(service_counts)
with open("output/interfaces.json", "w") as f:
    json.dump(interfaces, f, indent=4)

print("output/interfaces.json")
print(f"Interfaces fundet: {len(interfaces)}")
with open("output/access_groups.json", "w") as f:
    json.dump(access_groups, f, indent=4)

print("output/access_groups.json")
print(f"Access-groups fundet: {len(access_groups)}")