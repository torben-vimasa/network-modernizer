from engines.topology_engine import TopologyEngine


engine = TopologyEngine()

tests = [

    "10.255.255.17",

    "10.255.255.1",

    "172.27.57.5",

]

print()
print("Topology Engine")
print("=" * 40)

for hop in tests:

    result = engine.resolve_router(hop)

    print()

    print(hop)

    if result:

        print(result["router"])

        print(result["vrf"])

    else:

        print("Unknown")