class TraceReporter:

    def __init__(self, result):
        self.result = result

    def print_console(self):

        print()
        print("TRACE REPORT")
        print("=" * 60)

        self._print_network_path()
        self._print_decisions()
        self._print_trace_log()

    def _print_network_path(self):

        print()
        print("NETWORK PATH")
        print("-" * 60)

        if not self.result or not self.result.network_hops:
            print("No network hops")
            return

        for hop in self.result.network_hops:

            print()
            print(f"Hop {hop.hop_number}: {hop.hop_type.upper()}")

            if hop.device:
                print(f"Device   : {hop.device}")

            if hop.context:
                print(f"Context  : {hop.context}")

            if hop.vrf:
                print(f"VRF      : {hop.vrf}")

            if hop.ingress_interface:
                print(f"Ingress  : {hop.ingress_interface}")

            if hop.egress_interface:
                print(f"Egress   : {hop.egress_interface}")

            if hop.route:
                print(f"Route    : {hop.route}")

            if hop.next_hop:
                print(f"Next hop : {hop.next_hop}")

            if hop.reason:
                print(f"Reason   : {hop.reason}")

    def _print_decisions(self):

        print()
        print("DECISIONS")
        print("-" * 60)

        if not self.result or not self.result.network_hops:
            print("No decisions")
            return

        self._print_security_decision()
        self._print_nat_decision()

        for hop in self.result.network_hops:

            if hop.hop_type == "router":
                print(f"✓ Router route lookup on {hop.device}: {hop.route}")

            if hop.hop_type == "firewall":

                if hop.policy:
                    print(f"✓ Firewall policy: {hop.policy}")

                if hop.acl_rule:
                    print(f"✓ Firewall ACL rule: {hop.acl_rule}")

                if hop.nat_rule:
                    print(f"✓ Firewall NAT rule: {hop.nat_rule}")

                if hop.route_lookup:
                    print(f"✓ Firewall route lookup: {hop.route_lookup}")

                if hop.egress_interface:
                    print(f"✓ Firewall egress: {hop.egress_interface}")

    def _print_security_decision(self):

        security = getattr(self.result, "security", None)

        if not security:
            return

        if getattr(security, "permitted", False):
            print(f"✓ ACL permit: {security.reason}")
        else:
            print(f"✗ ACL deny: {security.reason}")

    def _print_nat_decision(self):

        steps = self._get_steps()

        nat_decision = None
        nat_source = None
        nat_destination = None

        for step in steps:
            if step.startswith("NAT decision:"):
                nat_decision = step.replace("NAT decision:", "").strip()

            if step.startswith("NAT source:"):
                nat_source = step.replace("NAT source:", "").strip()

            if step.startswith("NAT destination:"):
                nat_destination = step.replace("NAT destination:", "").strip()

        if nat_decision:
            print(f"✓ NAT decision: {nat_decision}")

        if nat_source:
            print(f"✓ NAT source: {nat_source}")

        if nat_destination:
            print(f"✓ NAT destination: {nat_destination}")

    def _print_trace_log(self):

        print()
        print("TRACE LOG")
        print("-" * 60)

        steps = self._get_steps()

        if not steps:
            print(self.result.explanation)
            return

        for index, step in enumerate(steps, start=1):
            print(f"{index:02d}. {step}")

    def _get_steps(self):

        explanation = getattr(self.result, "explanation", None)

        if not explanation:
            return []

        return getattr(explanation, "steps", []) or []