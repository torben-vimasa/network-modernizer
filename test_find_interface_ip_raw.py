from pathlib import Path


file = Path("data/router_raw/OBvDCPe1-20260424.txt")

patterns = [
    "172.21.2.26",
    "172.21.2.",
    "172.21.2.16",
    "172.21.2.24",
]

print()
print("Find Interface IP Raw")
print("=" * 60)

with open(file, encoding="utf-8", errors="ignore") as f:
    lines = f.readlines()

for pattern in patterns:

    print()
    print("Pattern:", pattern)
    print("-" * 60)

    found = 0

    for index, line in enumerate(lines):

        if pattern in line:

            start = max(0, index - 5)
            end = min(len(lines), index + 6)

            for i in range(start, end):
                print(f"{i+1:06d}: {lines[i].rstrip()}")

            found += 1
            print()

            if found >= 3:
                break

    if found == 0:
        print("No matches")