from pathlib import Path

from parsers.route_parser import RouteParser

parser = RouteParser()

for file in Path("data/router_routes").glob("*"):
    routes = parser.parse_route_table(
        router_name=file.stem,
        lines=file.read_text(
            encoding="utf-8",
            errors="ignore"
        ).splitlines()
    )

    print()
    print(file.stem)
    print("=" * 60)
    print("Routes:", len(routes))

    for r in routes:
        if (
            r.vrf == "SPNS2-TRANSIT-JTTN"
            and r.prefix.startswith("100.72.")
        ):
            print(r)