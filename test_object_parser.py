import json
from pathlib import Path

from parsers.object_group_parser import ObjectParser


contexts_dir = Path("data/contexts")
output_dir = Path("output")
output_dir.mkdir(exist_ok=True)

parser = ObjectParser()

all_objects = []
all_groups = []

for context_file in contexts_dir.glob("*.txt"):
    context_name = context_file.stem

    with open(context_file, "r", encoding="utf-8", errors="ignore") as f:
        lines = f.readlines()

    objects, groups = parser.parse_context_file(context_name, lines)

    all_objects.extend(objects)
    all_groups.extend(groups)

objects_json = [
    {
        "name": obj.name,
        "type": obj.object_type,
        "value": obj.value
    }
    for obj in all_objects
]

groups_json = [
    {
        "name": group.name,
        "members": group.members
    }
    for group in all_groups
]

with open(output_dir / "network_objects.json", "w") as f:
    json.dump(objects_json, f, indent=4)

with open(output_dir / "object_groups.json", "w") as f:
    json.dump(groups_json, f, indent=4)

print("Object Parser")
print("-------------")
print(f"Network objects: {len(all_objects)}")
print(f"Object groups:   {len(all_groups)}")
print("Output gemt:")
print("output/network_objects.json")
print("output/object_groups.json")

print("\nTop object groups")
print("-----------------")

top_groups = sorted(
    all_groups,
    key=lambda g: len(g.members),
    reverse=True
)[:10]

for group in top_groups:
    print(f"{group.name}: {len(group.members)} members")