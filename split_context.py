from pathlib import Path
import re

input_file = Path("data/all_contexts.log")
output_dir = Path("data/contexts")
output_dir.mkdir(exist_ok=True)

with open(input_file, "r", encoding="utf-8", errors="ignore") as f:
    raw_lines = f.readlines()

clean_lines = []

for line in raw_lines:
    line = line.rstrip()

    if line.startswith("=~=~=~"):
        continue

    if "<--- More --->" in line:
        continue

    if line.strip() == "":
        continue

    clean_lines.append(line)

contexts = {}
current_context = None
current_lines = []

for line in clean_lines:
    if line.startswith("hostname "):
        if current_context and current_lines:
            contexts[current_context] = current_lines

        current_context = line.replace("hostname ", "").strip()
        current_lines = [line]
    else:
        if current_context:
            current_lines.append(line)

if current_context and current_lines:
    contexts[current_context] = current_lines

for context_name, lines in contexts.items():
    safe_name = re.sub(r"[^A-Za-z0-9_.-]", "_", context_name)
    output_file = output_dir / f"{safe_name}.txt"

    with open(output_file, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))

print("Contexts fundet:")
for name in contexts:
    print("-", name)

print(f"\nAntal contexts: {len(contexts)}")