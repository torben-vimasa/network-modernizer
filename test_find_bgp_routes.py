from pathlib import Path
import re

route_line = re.compile(r"^\s*[\*>sdhrbi ]+\s*[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/\d+")

for file in Path("data/router_raw").glob("*.txt"):

    print()
    print(file)
    print("=" * 80)

    count = 0

    with open(file, encoding="utf-8", errors="ignore") as f:
        for line in f:
            if route_line.match(line):
                print(line.rstrip())
                count += 1

                if count >= 40:
                    break

    print("Route-like BGP lines shown:", count)