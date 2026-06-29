from parsers.asa_nat_parser import ASANATParser


parser = ASANATParser()

line = "nat (inside,outside) source static OBJ_REAL OBJ_NAT"

rule = parser.parse_line(line)

print()
print("ASA NAT Parser Test")
print("=" * 50)

print("Direction         :", rule.direction)
print("Source original   :", rule.source_original)
print("Source translated :", rule.source_translated)
print("Reason            :", rule.reason)
print("Raw               :", rule.raw)