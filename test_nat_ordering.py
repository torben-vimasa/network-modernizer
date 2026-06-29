from engines.nat_engine import NATEngine
from models.nat_rule import NATRule


rules = [
    NATRule(name="AFTER", section="after-auto"),
    NATRule(name="AUTO", section="auto"),
    NATRule(name="MANUAL", section="manual"),
]

engine = NATEngine(rules)

print()
print("NAT Ordering")
print("=" * 50)

for rule in engine.rules:
    print(rule.name, rule.section)