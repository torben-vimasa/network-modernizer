from inventory.inventory_loader import InventoryLoader
from inventory.inventory_validator import InventoryValidator


firewalls = InventoryLoader().load_firewalls()

findings = InventoryValidator(firewalls).validate_firewalls()

print()
print("Inventory Validator")
print("=" * 60)

print("Findings:", len(findings))

for finding in findings:
    print()
    print("Severity:", finding["severity"])
    print("Item    :", finding["item"])
    print("Message :", finding["message"])