from parsers.asa_nat_parser import ASANATParser


parser = ASANATParser()

line = (
    "nat (inside,outside) after-auto "
    "source static SRC_REAL SRC_NAT "
    "destination static DST_REAL DST_NAT "
    "service TCP80 TCP8080"
)

rule = parser.parse_line(line)

print()
print("ASA NAT Parser Test")
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

print("Service original      :", rule.service_original)
print("Service translated    :", rule.service_translated)

print()

print("Reason                :", rule.reason)