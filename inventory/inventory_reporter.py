from datetime import datetime

from inventory.inventory_validator import InventoryValidator


class InventoryReporter:

    def __init__(self, firewalls):
        self.firewalls = firewalls
        self.findings = InventoryValidator(firewalls).validate_firewalls()

    def print_firewall_report(self):

        print()
        print("FIREWALL INVENTORY REPORT")
        print("=" * 60)

        print("Firewalls :", len(self.firewalls))
        print("Contexts  :", self._count_contexts())
        print("Warnings  :", self._count_warnings())
        print("Findings  :", len(self.findings))

        self._print_findings()

        print()
        print("FIREWALLS")
        print("-" * 60)

        for firewall in self.firewalls:
            self._print_firewall(firewall)

    def _print_findings(self):

        if not self.findings:
            return

        print()
        print("INVENTORY FINDINGS")
        print("-" * 60)

        for finding in self.findings:
            print(
                f"{finding['severity'].upper():8} "
                f"{finding['item']}: "
                f"{finding['message']}"
            )

    def _print_firewall(self, firewall):

        contexts = firewall.properties.get("contexts", [])

        print()
        print(firewall.name)
        print("-" * 60)
        print("Vendor     :", firewall.vendor)
        print("Platform   :", firewall.platform)
        print("Site       :", firewall.site)
        print("Environment:", firewall.environment)
        print("Role       :", firewall.role)
        print("Status     :", firewall.status)
        print("Confidence :", firewall.confidence)
        print("Config file:", firewall.config_file)
        print("Config date:", firewall.config_date)
        print("Import date:", firewall.import_date)
        print("Age days   :", self._age_days(firewall.config_date))
        print("Contexts   :", len(contexts))

        for context in contexts:
            print("  -", context)

        if firewall.warnings:
            print("Warnings   :")
            for warning in firewall.warnings:
                print("  !", warning)

    def _count_contexts(self):
        return sum(
            len(firewall.properties.get("contexts", []))
            for firewall in self.firewalls
        )

    def _count_warnings(self):
        return sum(
            len(firewall.warnings)
            for firewall in self.firewalls
        )

    def _age_days(self, config_date):

        if not config_date:
            return "unknown"

        try:
            date = datetime.fromisoformat(config_date)
        except ValueError:
            return "invalid"

        return (datetime.now() - date).days