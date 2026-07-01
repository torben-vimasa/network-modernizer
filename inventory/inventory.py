from inventory.inventory_loader import InventoryLoader
from inventory.firewall_inventory import FirewallInventory
from inventory.inventory_validator import InventoryValidator


class Inventory:

    def __init__(self):

        self.loader = InventoryLoader()

        self._firewalls = self.loader.load_firewalls()

        self.firewall_inventory = FirewallInventory(self._firewalls)

        self.validator = InventoryValidator(self._firewalls)

    # ---------------------------------------------------------

    def firewalls(self):
        return self._firewalls

    # ---------------------------------------------------------

    def firewall(self, name):

        for firewall in self._firewalls:
            if firewall.name == name:
                return firewall

        return None

    # ---------------------------------------------------------

    def context(self, context_name):
        return self.firewall_inventory.find_by_context(context_name)

    # ---------------------------------------------------------

    def findings(self):
        return self.validator.validate_firewalls()

    # ---------------------------------------------------------

    def statistics(self):

        return {
            "firewalls": len(self._firewalls),
            "contexts": sum(
                len(f.properties.get("contexts", []))
                for f in self._firewalls
            ),
            "findings": len(self.findings())
        }