from loaders.asa_config_loader import ASAConfigLoader

loader = ASAConfigLoader()

lines = loader.load("data/asa_nat_sample.txt")

print()
print("ASA Loader")
print("=" * 50)

print("Lines:", len(lines))

print()

for line in lines:
    print(line)