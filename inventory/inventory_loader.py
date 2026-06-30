import json
from pathlib import Path

from models.inventory_item import InventoryItem


class InventoryLoader:

    def __init__(self, knowledge_dir=Path("knowledge")):
        self.knowledge_dir = Path(knowledge_dir)

    def load_firewalls(self):

        file = self.knowledge_dir / "firewall_inventory.json"

        with open(file, encoding="utf-8") as f:
            raw_items = json.load(f)

        items = []

        for item in raw_items:
            inventory_item = InventoryItem(
                name=item["name"],
                item_type=item.get("item_type", "firewall"),
                vendor=item.get("vendor"),
                platform=item.get("platform"),
                site=item.get("site"),
                environment=item.get("environment"),
                role=item.get("role"),
                config_file=item.get("config_file"),
                config_date=item.get("config_date"),
                status=item.get("status", "unknown"),
                confidence=item.get("confidence", "unknown"),
                warnings=item.get("warnings", []),
                properties={
                    "contexts": item.get("contexts", [])
                }
            )

            items.append(inventory_item)

        return items