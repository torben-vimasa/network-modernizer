from parsers.asa_nat_parser import ASANATParser


parser = ASANATParser()

line = (
    "nat (inside,outside) "
    "source dynamic CLIENTS PAT_POOL"
)

rule = parser.parse_line(line)

print()
print("ASA Dynamic NAT")
print("=" * 50)

print("Section      :", rule.section)
print("Direction    :", rule.direction)

print()

print("Source orig  :", rule.source_original)
print("Source trans :", rule.source_translated)

print()

print("Reason       :", rule.reason)