from pathlib import Path

from parsers.bgp_parser import BGPParser


parser = BGPParser()

file = Path("data/router_raw/OBvDCPe1-20260424.txt")

with open(file, encoding="utf-8", errors="ignore") as f:
    routes = parser.parse(
        f.readlines(),
        source_router=file.stem,
        vrf="unknown"
    )

print()
print("Real BGP File Parser")
print("=" * 50)

print("File  :", file)
print("Routes:", len(routes))

print()

for route in routes[:20]:
    print(route)