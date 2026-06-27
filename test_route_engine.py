from engines.route_engine import RouteEngine


engine = RouteEngine()

tests = [
    {
        "router": "RGDCPe1",
        "vrf": "CS",
        "destination": "100.72.36.70"
    },
    {
        "router": "RGDCPe1",
        "vrf": "default",
        "destination": "172.21.65.116"
    },
]

print()
print("Route Engine Test")
print("=" * 40)

for test in tests:
    print()
    print(f'{test["router"]} VRF={test["vrf"]} destination={test["destination"]}')
    print("-" * 40)

    route = engine.lookup(
        test["router"],
        test["vrf"],
        test["destination"]
    )

    if route:
        print(f'Matched route: {route["prefix"]}')
        print(f'Next hop:      {route["next_hop"]}')
        print(f'Protocol:      {route["protocol"]}')
    else:
        print("No route found")