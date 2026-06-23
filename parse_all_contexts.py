import json
from pathlib import Path

contexts_dir = Path("data/contexts")
output_dir = Path("output")

output_dir.mkdir(exist_ok=True)

context_files = list(contexts_dir.glob("*.txt"))

all_contexts = []

print(f"Contexts fundet: {len(context_files)}")
for context_file in context_files:
    context_name = context_file.stem

    with open(context_file, "r", encoding="utf-8", errors="ignore") as f:
        lines = f.readlines()
    
    access_list_count = 0
    object_count = 0
    interface_count = 0

    for line in lines:
        line = line.strip()

        if line.startswith("access-list "):
            access_list_count += 1

        if line.startswith("object network"):
            object_count += 1

        if line.startswith("interface "):
            interface_count += 1

    print(
    f"{context_name}: "
    f"{access_list_count} ACLs, "
    f"{object_count} objects, "
    f"{interface_count} interfaces"
)