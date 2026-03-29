import threading
from prefetch.extractor import HTMLDependencyExtractor

class DependencyGraph:
    def __init__(self):
        # adjacency list: domain → set of dependencies
        self.graph = {}
        self.extractor = HTMLDependencyExtractor() 
        self.lock = threading.Lock() 

    def add_dependency(self, domain, dependencies):
        """
        Add domain → dependencies mapping
        """
        with self.lock:
            if domain not in self.graph:
                self.graph[domain] = set()

        for dep in dependencies:
            if dep != domain:
                self.graph[domain].add(dep)

    def get_dependencies(self, domain):
        return list(self.graph.get(domain, []))

    def print_graph(self):
        print("\n--- Dependency Graph ---")
        for domain, deps in self.graph.items():
            print(f"{domain} → {list(deps)}")

    def build_from_domain(self, domain):
        """
        Extract dependencies and store in graph
        """
        if domain in self.graph:
         return self.graph[domain]

        dependencies = self.extractor.extract_domains(domain)
        self.add_dependency(domain, dependencies)
        return dependencies
    
    def get_dependency_count(self, domain):
        """
        Return number of dependencies of a domain
        """
        return len(self.graph.get(domain, []))


    def most_dependent_domain(self):
        """
        Return domain with maximum dependencies
        """
        if not self.graph:
            return None
        return max(self.graph, key=lambda d: len(self.graph[d]))


    def get_max_depth(self, domain, visited=None):
        """
        Calculate maximum dependency chain depth
        """
        if visited is None:
            visited = set()

        if domain in visited:
            return 0
        
        if domain not in self.graph:
            return 0

        visited.add(domain)

        max_depth = 0
        for dep in self.graph[domain]:
            depth = 1 + self.get_max_depth(dep, visited)
            max_depth = max(max_depth, depth)

        visited.remove(domain)  

        return max_depth


    def total_domains(self):
        """
        Return total number of domains in graph
        """
        return len(self.graph)


    def print_summary(self):
        """
        Print number of dependencies for each domain
        """
        print("\n--- Graph Summary ---")
        for domain in self.graph:
            print(f"{domain}: {len(self.graph[domain])} dependencies")