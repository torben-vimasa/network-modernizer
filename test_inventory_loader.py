from inventory.inventory_loader import InventoryLoader


loader = InventoryLoader()

firewalls = loader.load_firewalls()

print()
print("Inventory Loader")
print("=" * 60)

print("Firewalls:", len(firewalls))

for firewall in firewalls:
    print()
    print("Name       :", firewall.name)
    print("Type       :", firewall.item_type)
    print("Site       :", firewall.site)
    print("Status     :", firewall.status)
    print("Confidence :", firewall.confidence)
    print("Contexts   :", firewall.properties.get("contexts"))
    print("Warnings   :", firewall.warnings)