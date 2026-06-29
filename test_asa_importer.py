from importers.asa_importer import ASAImporter

importer = ASAImporter()

result = importer.import_config(
    "data/router_raw/OBvDCPe1-20260424.txt"
)

print()
print("ASA Importer")
print("=" * 50)

print("NAT Rules :", len(result.nat_rules))
print("BGP Routes:", len(result.bgp_routes))

print()

for route in result.bgp_routes[:10]:
    print(route)