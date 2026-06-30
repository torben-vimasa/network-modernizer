from importers.router_importer import RouterImporter

importer = RouterImporter()

result = importer.import_router(
    "data/router_raw/OBvDCPe1-20260424.txt"
)

print()
print("Router Importer")
print("=" * 60)

print("Routes     :", len(result.routes))
print("BGP        :", len(result.bgp_routes))
print("Interfaces :", len(result.interfaces))

print()

if result.interfaces:
    print("First interface")
    print(result.interfaces[0])

if result.bgp_routes:
    print()
    print("First BGP route")
    print(result.bgp_routes[0])

if result.routes:
    print()
    print("First static route")
    print(result.routes[0])