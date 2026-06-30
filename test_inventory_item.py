from models.inventory_item import InventoryItem


item = InventoryItem(
    name="BHASA1",
    item_type="firewall",
    vendor="Cisco",
    platform="ASA",
    site="JTTN",
    environment="IT",
    role="multi-context firewall",
    config_file="data/contexts/BDK-Mgmt.txt",
    config_date="2026-06-24",
    status="partial",
    confidence="medium",
    warnings=[
        "Missing system context",
        "Config date not verified"
    ],
    properties={
        "contexts": [
            "BDK-Mgmt",
            "BDK-Teknik",
            "BDK-Enterprise",
            "BDK-DSB",
            "Site2Site-VPN"
        ]
    }
)

item.mark_imported_now()

print()
print("Inventory Item")
print("=" * 60)
print(item)