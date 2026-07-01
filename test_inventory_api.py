from inventory.inventory import Inventory


inventory = Inventory()

print()
print("Inventory API")
print("=" * 60)

print()

print(inventory.statistics())

print()

fw = inventory.firewall("BHASA1")

print("Firewall")
print("-------------------------------------")
print(fw)

print()

ctx = inventory.context("BDK-Mgmt")

print("Context")
print("-------------------------------------")
print(ctx)

print()

print("Findings")
print("-------------------------------------")

for finding in inventory.findings():
    print(finding)