from pathlib import Path


patterns = [
    "172.21.2.26",
    "172.21.2.24",
    "172.21.2.16/28",
    "172.21.2.16"
]

for pattern in patterns:

    print()
    print("Pattern:", pattern)
    print("=" * 80)

    found = 0

    for file in Path("data").rglob("*.txt"):

        with open(file, encoding="utf-8", errors="ignore") as f:
            lines = f.readlines()

        for index, line in enumerate(lines):

            if pattern in line:

                print()
                print(file)
                print("-" * 80)

                start = max(0, index - 4)
                end = min(len(lines), index + 5)

                for i in range(start, end):
                    print(f"{i+1:06d}: {lines[i].rstrip()}")

                found += 1

                if found >= 10:
                    break

        if found >= 10:
            break

    if found == 0:
        print("No matches")