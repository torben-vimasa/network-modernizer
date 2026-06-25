import json
from pathlib import Path

from parsers.acl_rule_parser import ACLRuleParser

with open(Path("output/rules.json"), "r") as f:
    raw_rules = json.load(f)

parser = ACLRuleParser()
acls = parser.parse_rules(raw_rules)

print("ACL Rule Parser")
print("---------------")
print(f"ACLs fundet: {len(acls)}")

total_rules = sum(len(acl.rules) for acl in acls)
print(f"Regler fundet: {total_rules}")

top_acls = sorted(
    acls,
    key=lambda acl: len(acl.rules),
    reverse=True
)[:10]

print("\nTop ACLs")
print("--------")

for acl in top_acls:
    hitcnt_zero = len([
        rule for rule in acl.rules
        if rule.hitcnt == 0
    ])

    print(
        f"{acl.name}: "
        f"{len(acl.rules)} rules, "
        f"hitcnt=0: {hitcnt_zero}"
    )