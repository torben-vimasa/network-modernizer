from engines.firewall_route_engine import FirewallRouteEngine

from models.route_entry import RouteEntry


routes = [
    RouteEntry(
        router="BHASA1",
        vrf="BDK-Mgmt",
        prefix="0.0.0.0/0",
        next_hop="172.21.2.62",
        protocol="static"
    ),
    RouteEntry(
        router="BHASA1",
        vrf="BDK-Mgmt",
        prefix="100.72.36.64/27",
        next_hop="172.21.2.26",
        protocol="static"
    )
]

engine = FirewallRouteEngine(routes)

result = engine.lookup(
    "100.72.36.70"
)

print()
print("Firewall Route Engine")
print("=" * 60)

print("Matched :", result.matched)
print("Reason  :", result.reason)

if result.route:
    print("Route   :", result.route.prefix)
    print("NextHop :", result.next_hop)