from api.digital_twin import DigitalTwin

dt = DigitalTwin()

exp = dt.route.explain(
    "RGDCPe1",
    "CS",
    "100.72.36.70"
)

print()
print("Route Explanation")
print("=" * 40)

print(exp.destination)
print(exp.matched_prefix)
print(exp.protocol)
print(exp.next_hop)
print(exp.reason)