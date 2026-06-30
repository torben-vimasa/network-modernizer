from datetime import datetime


class InventoryValidator:

    def __init__(self, firewalls):
        self.firewalls = firewalls

    def validate_firewalls(self):

        findings = []

        for firewall in self.firewalls:
            findings.extend(
                self._validate_firewall(firewall)
            )

        return findings

    def _validate_firewall(self, firewall):

        findings = []

        if not firewall.properties.get("contexts"):
            findings.append(
                {
                    "severity": "critical",
                    "item": firewall.name,
                    "message": "Firewall has no contexts defined"
                }
            )

        if not firewall.config_date:
            findings.append(
                {
                    "severity": "warning",
                    "item": firewall.name,
                    "message": "Firewall config date is missing"
                }
            )

        age = self._age_days(firewall.config_date)

        if isinstance(age, int) and age > 30:
            findings.append(
                {
                    "severity": "warning",
                    "item": firewall.name,
                    "message": f"Firewall config is {age} days old"
                }
            )

        for warning in firewall.warnings:
            findings.append(
                {
                    "severity": "info",
                    "item": firewall.name,
                    "message": warning
                }
            )

        return findings

    def _age_days(self, config_date):

        if not config_date:
            return None

        try:
            date = datetime.fromisoformat(config_date)
        except ValueError:
            return None

        return (datetime.now() - date).days