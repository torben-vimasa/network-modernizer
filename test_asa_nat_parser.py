from parsers.asa_nat_parser import ASANATParser


parser = ASANATParser()

line = "nat (inside,outside) source static SRC_REAL SRC_NAT destination static DST_NAT DST_REAL"

rule = parser.parse_line(line)

print()
print("ASA NAT Parser Test")
print("=" * 50)

print(rule)