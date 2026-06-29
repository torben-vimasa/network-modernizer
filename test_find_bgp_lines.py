from pathlib import Path


for file in Path("data/router_raw").glob("*.txt"):

    print()
    print(file)
    print("=" * 80)

    count = 0

    with open(file, encoding="utf-8", errors="ignore") as f:
        for line in f:
            if "bgp" in line.lower() or "BGP" in line:
                print(line.rstrip())
                count += 1

                if count >= 40:
                    break

    print("BGP lines shown:", count)