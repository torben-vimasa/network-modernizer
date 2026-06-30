class FirewallInventory:

    def __init__(self, firewalls):
        self.firewalls = firewalls

    def find_by_context(self, context_name):

        for firewall in self.firewalls:
            contexts = firewall.properties.get("contexts", [])

            if context_name in contexts:
                return firewall

        return None