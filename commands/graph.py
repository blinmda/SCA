import json
import networkx as nx
import matplotlib.pyplot as plt
import json
from core.interactive_graph import visualize_graph
from core.dependency_tree import build_tree, format_paths_for_console

def run_graph_command(p_name, p_ver, sbom_file, interactive):
    all_paths, id_to_label = build_tree(sbom_file, p_name, p_ver)
    if not all_paths or not id_to_label:
        exit()
    result_string = format_paths_for_console(all_paths, id_to_label)
    
    if all_paths:
        print(f'\n\ndependency paths:')
        print(f'-----------------')
        print(f'{result_string}\n\n')
        
        G = create_networkx_graph(all_paths, id_to_label)
        
        if interactive: visualize_graph(G, p_name)
        else: simple_visualize_graph(G, p_name)
    
    
def create_networkx_graph(paths, id_to_label):
    G = nx.DiGraph()
    
    start_nodes = {id_to_label.get(path[0], path[0]) for path in paths if len(path) > 0}
    
    for path in paths:
        for i in range(len(path) - 1):
            source = id_to_label.get(path[i], path[i])
            target = id_to_label.get(path[i + 1], path[i + 1])
            G.add_edge(source, target)
    
    for node in G.nodes():
        G.nodes[node]['is_start'] = (node in start_nodes)
        G.nodes[node]['is_sink'] = (G.out_degree(node) == 0)
    
    return G

def calculate_node_positions(G):
    pos = {}
    node_colors = []
    edge_colors = []
    
    try:
        sources = [n for n, d in G.in_degree() if d == 0]
        sinks = [n for n, d in G.out_degree() if d == 0]
        
        node_to_level = {}
        for root in sources:
            curr_levels = nx.single_source_shortest_path_length(G, root)
            for node, lvl in curr_levels.items():
                node_to_level[node] = min(node_to_level.get(node, float('inf')), lvl)
        
        max_lvl = max(node_to_level.values()) if node_to_level else 0
        for node in sinks:
            node_to_level[node] = max_lvl + 1
        
        level_counts = {}
        for node, lvl in node_to_level.items():
            level_counts[lvl] = level_counts.get(lvl, 0) + 1

        current_offsets = {lvl: 0 for lvl in level_counts}
        
        for node in G.nodes():
            lvl = node_to_level.get(node, 0)
            width = level_counts.get(lvl, 1)
            pos[node] = (current_offsets[lvl] - width / 2, -lvl)
            current_offsets[lvl] += 1
            
            if G.nodes[node].get('is_start'):
                node_colors.append("lightgreen")
            else:
                node_colors.append("skyblue")
            
            if G.nodes[node].get('is_sink'):
                edge_colors.append("red")
            else:
                edge_colors.append("none")
    
    except Exception:
        pos = nx.spring_layout(G)
        node_colors = ["lightgreen" if G.nodes[n].get('is_start') else "skyblue" for n in G.nodes()]
        edge_colors = ["red" if G.nodes[n].get('is_sink') else "none" for n in G.nodes()]
    
    return pos, node_colors, edge_colors

def simple_visualize_graph(G, p_name):
    if not G.nodes():
        print("Нет узлов для визуализации")
        return
    
    pos, node_colors, borders = calculate_node_positions(G)
    
    plt.figure(figsize=(14, 10))
    nx.draw(G, pos, with_labels=True, node_size=4000,
            node_color=node_colors, edgecolors=borders,
            linewidths=2.0, font_size=8,
            font_weight="bold", arrows=True,
            arrowsize=20, edge_color="gray")
    
    plt.title(f"Полный граф зависимостей для {p_name}")
    plt.tight_layout()
    plt.show()