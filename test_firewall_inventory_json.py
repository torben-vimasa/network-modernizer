import json
from pathlib import Path


file = Path("knowledge/firewall_inventory.json")

with open(file, encoding="utf-8") as f:
    firewalls = json.load(f)

print()
print("Firewall Inventory JSON")
print("=" * 60)

print("Firewalls:", len(firewalls))

for firewall in firewalls:
    print()
    print("Firewall :", firewall["name"])
    print("Site     :", firewall.get("site"))
    print("Contexts :", len(firewall.get("contexts", [])))
    print("Status   :", firewall.get("status"))
    print("Warnings :", len(firewall.get("warnings", [])))