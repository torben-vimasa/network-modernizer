from importers.asa_importer import ASAImporter

importer = ASAImporter()

result = importer.import_config(
    "data/asa_nat_sample.txt"
)

print()
print("ASA Importer")
print("=" * 50)

print("NAT Rules :", len(result["nat_rules"]))

for rule in result["nat_rules"]:
    print(rule)