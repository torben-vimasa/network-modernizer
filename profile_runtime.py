import time

from api.digital_twin import DigitalTwin
from pilot_runner import (
    evaluate_expectations,
    load_pilot_files,
    normalize_pilot,
    run_trace
)


start = time.perf_counter()

twin = DigitalTwin()

graph_loaded = time.perf_counter()

pilots = [
    normalize_pilot(pilot)
    for pilot in load_pilot_files(
        __import__("pathlib").Path(
            "pilots/pilot_flows_combined.json"
        )
    )
]

pilots_loaded = time.perf_counter()

for pilot in pilots:
    result = run_trace(twin, pilot)
    evaluate_expectations(pilot, result)

finished = time.perf_counter()

print()
print("RUNTIME PROFILE")
print("=" * 60)
print(
    f"Knowledge Graph : "
    f"{graph_loaded - start:.3f} seconds"
)
print(
    f"Pilot loading   : "
    f"{pilots_loaded - graph_loaded:.3f} seconds"
)
print(
    f"31 pilot traces : "
    f"{finished - pilots_loaded:.3f} seconds"
)
print(
    f"Total           : "
    f"{finished - start:.3f} seconds"
)