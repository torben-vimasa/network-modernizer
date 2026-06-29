from parsers.asa_nat_parser import ASANATParser

parser = ASANATParser()

line = (
    "nat (inside,outside) "
    "source static CLIENT_REAL CLIENT_NAT "
    "destination static SERVER_REAL SERVER_NAT"
)

rule = parser.parse_line(line)

print()
print("ASA Twice NAT")
print("=" * 50)

print("Section               :", rule.section)
print("Direction             :", rule.direction)

print()

print("Source original       :", rule.source_original)
print("Source translated     :", rule.source_translated)

print()

print("Destination original  :", rule.destination_original)
print("Destination translated:", rule.destination_translated)

print()

print("Reason                :", rule.reason)