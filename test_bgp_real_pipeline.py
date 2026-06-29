from pathlib import Path

from engines.bgp_engine import BGPEngine
from parsers.bgp_parser import BGPParser


file = Path("data/router_raw/OBvDCPe1-20260424.txt")

with open(file, encoding="utf-8", errors="ignore") as f:
    routes = BGPParser().parse(
        f.readlines(),
        source_router=file.stem,
        vrf="unknown"
    )

engine = BGPEngine(routes)

result = engine.lookup(
    destination="10.30.9.152",
    vrf="unknown"
)

print()
print("Real BGP Pipeline")
print("=" * 50)

print("Routes :", len(routes))
print("Matched:", result.matched)
print("Reason :", result.reason)

if result.route:
    print("Prefix :", result.route.prefix)
    print("NextHop:", result.route.next_hop)
    print("Router :", result.route.source_router)
    print("VRF    :", result.route.vrf)