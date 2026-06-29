from parsers.asa_nat_parser import ASANATParser


parser = ASANATParser()

line = "nat (inside,outside) source static SRC_REAL SRC_NAT destination static DST_NAT DST_REAL"

rule = parser.parse_line(line)

print()
print("ASA NAT Parser Test")
print("=" * 50)

print("Direction              :", rule.direction)
print("Source original        :", rule.source_original)
print("Source translated      :", rule.source_translated)
print("Destination original   :", rule.destination_original)
print("Destination translated :", rule.destination_translated)
print("Reason                 :", rule.reason)
print("Raw                    :", rule.raw)