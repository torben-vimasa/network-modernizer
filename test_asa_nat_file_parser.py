from parsers.asa_nat_parser import ASANATParser

parser = ASANATParser()

rules = parser.parse_file("data/asa_nat_sample.txt")

print()
print("ASA NAT File Parser")
print("=" * 50)

print("Rules:", len(rules))

for rule in rules:
    print(rule)