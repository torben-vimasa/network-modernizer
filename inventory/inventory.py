from inventory.firewall_inventory import FirewallInventory
from inventory.inventory_loader import InventoryLoader
from inventory.inventory_validator import InventoryValidator

from models.inventory_statistics import InventoryStatistics


class Inventory:

    def __init__(self):

        self.loader = InventoryLoader()

        self._firewalls = self.loader.load_firewalls()

        self.firewall_inventory = FirewallInventory(self._firewalls)

        self.validator = InventoryValidator(self._firewalls)

    def firewalls(self):
        return self._firewalls

    def firewall(self, name):

        for firewall in self._firewalls:
            if firewall.name == name:
                return firewall

        return None

    def context(self, context_name):
        return self.firewall_inventory.find_by_context(context_name)

    def findings(self):
        return self.validator.validate_firewalls()

    def statistics(self):

        findings = self.findings()

        critical = sum(
            1
            for finding in findings
            if finding["severity"] == "critical"
        )

        warnings = sum(
            1
            for finding in findings
            if finding["severity"] == "warning"
        )

        info = sum(
            1
            for finding in findings
            if finding["severity"] == "info"
        )

        healthy_firewalls = sum(
            1
            for firewall in self._firewalls
            if not any(
                finding["item"] == firewall.name
                and finding["severity"] in ("critical", "warning")
                for finding in findings
            )
        )

        health_score = 100
        explanation = ["Start score: 100"]

        if critical:
            penalty = critical * 25
            health_score -= penalty
            explanation.append(f"-{penalty}: {critical} critical finding(s)")

        if warnings:
            penalty = warnings * 10
            health_score -= penalty
            explanation.append(f"-{penalty}: {warnings} warning finding(s)")

        if info:
            penalty = info * 2
            health_score -= penalty
            explanation.append(f"-{penalty}: {info} informational finding(s)")

        if health_score < 0:
            health_score = 0

        explanation.append(f"Final score: {health_score}")

        return InventoryStatistics(
            firewalls=len(self._firewalls),
            contexts=sum(
                len(firewall.properties.get("contexts", []))
                for firewall in self._firewalls
            ),
            findings=len(findings),
            critical=critical,
            warnings=warnings,
            info=info,
            healthy_firewalls=healthy_firewalls,
            health_score=health_score,
            health_explanation=explanation
        )