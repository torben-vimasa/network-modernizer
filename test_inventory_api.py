from inventory.inventory import Inventory


inventory = Inventory()

stats = inventory.statistics()

print()
print("Inventory API")
print("=" * 60)

print()
print("Statistics")
print("-------------------------------------")
print("firewalls           ", stats.firewalls)
print("contexts            ", stats.contexts)
print("findings            ", stats.findings)
print("critical            ", stats.critical)
print("warnings            ", stats.warnings)
print("info                ", stats.info)
print("healthy_firewalls   ", stats.healthy_firewalls)
print("health_score        ", stats.health_score)

print()
print("Health explanation")
print("-------------------------------------")

for line in stats.health_explanation:
    print(line)

print()
print("Firewall")
print("-------------------------------------")
print(inventory.firewall("BHASA1"))

print()
print("Context")
print("-------------------------------------")
print(inventory.context("BDK-Mgmt"))

print()
print("Findings")
print("-------------------------------------")

for finding in inventory.findings():
    print(finding)