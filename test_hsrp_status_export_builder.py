from builders.hsrp_status_export_builder import HSRPStatusExportBuilder

states = HSRPStatusExportBuilder().build()

print()
print("HSRP Status Export Builder")
print("=" * 60)
print("States:", len(states))
print("Output: output/hsrp_status.json")

for s in states:
    print(s)