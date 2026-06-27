from pathlib import Path

from parsers.router_inventory_parser import RouterInventoryParser


parser = RouterInventoryParser()

router_file = Path("data/router_raw/RGDCPe1-20260624.txt")

with open(router_file, encoding="utf-8", errors="ignore") as f:

    router = parser.parse(
        "RGDCPe1",
        f.readlines()
    )

print()

print(router.name)

print()

print(f"Interfaces: {len(router.interfaces)}")

print()

for interface in router.interfaces[:20]:

    print(interface)