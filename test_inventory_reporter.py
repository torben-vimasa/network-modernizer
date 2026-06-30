from inventory.inventory_loader import InventoryLoader
from inventory.inventory_reporter import InventoryReporter


firewalls = InventoryLoader().load_firewalls()

InventoryReporter(firewalls).print_firewall_report()