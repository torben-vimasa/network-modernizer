import json
from pathlib import Path

from parsers.route_parser import RouteParser


router_dir = Path("data/router_raw")
output_dir = Path("output")
output_dir.mkdir(exist_ok=True)

parser = RouteParser()

all_routes = []

for router_file in router_dir.glob("*.txt"):
    router_name = router_file.stem

    with open(router_file, "r", encoding="utf-8", errors="ignore") as f:
        lines = f.readlines()

    routes = parser.parse_router_config(router_name, lines)
    all_routes.extend(routes)

routes_json = [
    {
        "router": route.router,
        "vrf": route.vrf,
        "prefix": route.prefix,
        "next_hop": route.next_hop,
        "protocol": route.protocol
    }
    for route in all_routes
]

with open(output_dir / "routes.json", "w") as f:
    json.dump(routes_json, f, indent=4)

print("Route Parser")
print("------------")
print(f"Routes found: {len(all_routes)}")
print("Output saved: output/routes.json")

for route in all_routes[:20]:
    print(
        f"{route.router:12} "
        f"VRF={route.vrf:25} "
        f"{route.prefix:20} -> {route.next_hop}"
    )