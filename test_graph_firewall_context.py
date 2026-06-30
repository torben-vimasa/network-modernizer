from api.digital_twin import DigitalTwin


dt = DigitalTwin()

print()
print("Firewall -> Context")
print("=" * 60)

ctx = dt.graph.find("Context", "BDK-Mgmt")

print(ctx)

print()
print("Neighbors")
print("-" * 60)

for rel, node in dt.graph.neighbors(ctx.id):
    print(rel, node.type, node.name)