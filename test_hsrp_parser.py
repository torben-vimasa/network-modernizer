from pathlib import Path
from parsers.hsrp_parser import HSRPParser

for file in Path("data/router_raw_clean").glob("*.txt"):
    states = HSRPParser().parse(
        file.read_text(encoding="utf-8", errors="ignore").splitlines(),
        device=file.stem
    )

    print()
    print(file.stem)
    print("=" * 60)

    for s in states:
        if s.interface in ["Vlan859", "Vlan3100", "Vlan3101", "Vlan3102"]:
            print(s)