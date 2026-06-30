from inventory.firewall_inventory import FirewallInventory
from inventory.inventory_loader import InventoryLoader


firewalls = InventoryLoader().load_firewalls()

inventory = FirewallInventory(firewalls)

for context in [
    "BDK-Mgmt",
    "BDK-Teknik",
    "BDK-Enterprise",
    "BDK-DSB",
    "Site2Site-VPN",
    "Unknown-Context"
]:
    result = inventory.find_by_context(context)

    print()
    print("Context:", context)
    print("=" * 60)

    if result:
        print("Firewall :", result.name)
        print("Site     :", result.site)
        print("Status   :", result.status)
        print("Confidence:", result.confidence)
    else:
        print("Not found")