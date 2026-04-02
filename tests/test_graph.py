from graph.graph_builder import DependencyGraph

def test_add_and_get_dependencies():
    g = DependencyGraph()
    g.add_dependency("A", ["B", "C"])
    assert set(g.get_dependencies("A")) == {"B", "C"}

def test_dependency_count():
    g = DependencyGraph()
    g.add_dependency("A", ["B", "C"])
    assert g.get_dependency_count("A") == 2

def test_most_dependent():
    g = DependencyGraph()
    g.add_dependency("A", ["B", "C"])
    g.add_dependency("B", ["D"])
    assert g.most_dependent_domain() == "A"

def test_max_depth():
    g = DependencyGraph()
    g.add_dependency("A", ["B", "C"])
    g.add_dependency("B", ["D"])
    assert g.get_max_depth("A") == 2

def test_total_domains():
    g = DependencyGraph()
    g.add_dependency("A", ["B", "C"])
    g.add_dependency("B", ["D"])
    assert g.total_domains() == 2