import cProfile
import pstats

from builders.graph_builder import GraphBuilder


profiler = cProfile.Profile()
profiler.enable()

graph = GraphBuilder().build_from_vrf_inventory()

profiler.disable()

print()
print(f"Nodes         : {len(graph.nodes)}")
print(f"Relationships : {len(graph.relationships)}")
print()

stats = pstats.Stats(profiler)
stats.strip_dirs()
stats.sort_stats("cumulative")
stats.print_stats(30)