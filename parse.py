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

for line in lines:
    line = line.strip()

    if line.startswith("name "):
        name_count += 1

    if line.startswith("access-list "):
        access_list_count += 1

        parts = line.split()

        if len(parts) > 1:
            acl_name = parts[1]

            if acl_name not in acl_counts:
                acl_counts[acl_name] = 0

            acl_counts[acl_name] += 1

        if " any any" in line:
            any_any_rules.append(line)

    if line.startswith("object network"):
        object_count += 1

print("ASA Analyse")
print("------------")
print(f"Names: {name_count}")
print(f"Access Lists: {access_list_count}")
print(f"Objects: {object_count}")
print(f"Any-Any Rules: {len(any_any_rules)}")

for rule in any_any_rules:
    print(rule)

print("\nTop ACLs")
print("--------")

for acl, count in sorted(
    acl_counts.items(),
    key=lambda x: x[1],
    reverse=True
)[:10]:
    print(f"{acl}: {count}")
    report = {
    "names": name_count,
    "access_lists": access_list_count,
    "objects": object_count,
    "any_any_rules": len(any_any_rules),
    "top_acls": dict(
        sorted(
            acl_counts.items(),
            key=lambda x: x[1],
            reverse=True
        )[:10]
    )
}

with open("output/report.json", "w") as f:
    json.dump(report, f, indent=4)

print("Report gemt til output/report.json")
print("\nACL Count:", len(acl_counts))