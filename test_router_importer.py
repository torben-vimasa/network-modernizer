from importers.router_importer import RouterImporter

importer = RouterImporter()

result = importer.import_router(
    "data/router_raw/OBvDCPe1-20260424.txt"
)

print()
print("Router Importer")
print("=" * 60)

print("Routes :", len(result.routes))
print("BGP    :", len(result.bgp_routes))

print()

if result.bgp_routes:
    print(result.bgp_routes[0])

if result.routes:
    print(result.routes[0])