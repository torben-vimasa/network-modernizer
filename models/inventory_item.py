from dataclasses import dataclass, field
from datetime import datetime


@dataclass
class InventoryItem:

    name: str

    item_type: str

    vendor: str | None = None
    platform: str | None = None
    site: str | None = None
    environment: str | None = None
    role: str | None = None

    config_file: str | None = None
    config_date: str | None = None
    import_date: str | None = None

    status: str = "unknown"
    confidence: str = "unknown"

    warnings: list[str] = field(default_factory=list)

    properties: dict = field(default_factory=dict)

    def mark_imported_now(self):
        self.import_date = datetime.now().isoformat(timespec="seconds")