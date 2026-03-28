from graph.graph_builder import DependencyGraph

g = DependencyGraph()

g.add_dependency("A", ["B", "C"])
g.add_dependency("B", ["D"])
g.add_dependency("C", ["E"])

g.print_graph()

print("Dependency count A:", g.get_dependency_count("A"))
print("Most dependent:", g.most_dependent_domain())
print("Max depth from A:", g.get_max_depth("A"))
print("Total domains:", g.total_domains())

g.print_summary()