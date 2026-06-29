from parsers.bgp_parser import BGPParser


sample = [
    "*> 100.72.36.64/27    10.255.255.17",
    "*  100.72.0.0/16      10.255.255.1",
    "*> 172.21.0.0/16      172.17.75.246"
]

parser = BGPParser()

routes = parser.parse(sample)

print()
print("BGP Parser")
print("=" * 50)

for route in routes:
    print(route)