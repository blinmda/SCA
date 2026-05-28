import json
import networkx as nx
import matplotlib.pyplot as plt
import subprocess
from collections import defaultdict
import draw

trivy_path = "C:\\Users\\abmnild\\Desktop\\w\\trivy\\trivy.exe"

def run_trivy(src_dir, name, dev, vuln):
    output_file = f"{name}_sbom_tmp.json"
    cmd = [
        trivy_path, "fs",
        "--format", "cyclonedx",
        "--output", output_file,
        src_dir
    ]
    if dev:
        cmd.append("--include-dev-deps")
    if vuln:
        cmd.extend(["--scanners", "vuln"])

    try:
        subprocess.run(cmd, capture_output=True, text=True, check=True)
        return output_file
    except subprocess.CalledProcessError as e:
        print(f"Ошибка при выполнении trivy: {e}")
        print(f"stderr: {e.stderr}")
        return None
    except FileNotFoundError:
        print("Ошибка: trivy не найден.")
        return None

def build_package_index(data, p_name, p_ver):
    id_to_label = {}
    app_ids = []
    target_ids = []

    for comp in data.get('components', []):
        bom_ref = comp.get('bom-ref')
        if not bom_ref:
            continue
        group = comp.get('group', '')
        name = comp.get('name', '???')
        version = comp.get('version', '')

        if group:
            name = group + '/' + name
        
        if name and version:
            id_to_label[bom_ref] = f"{name} {version}".strip()
        elif name:
            id_to_label[bom_ref] = name
        else:
            id_to_label[bom_ref] = bom_ref
        
        if comp.get('type') == 'application':
            app_ids.append(bom_ref)
        
        if name == p_name and version == p_ver:
            target_ids.append(bom_ref)
    
    return id_to_label, app_ids, target_ids

def build_dependency_graph(data):
    adj = defaultdict(list)
    
    for dep in data.get('dependencies', []):
        parent = dep.get('ref')
        children = dep.get('dependsOn', [])
        
        for child in children:
            adj[parent].append(child)
    
    return adj

def find_all_paths_to_target(adj, start_nodes, target_ids):
    all_paths = []
    
    def dfs(current, target, path):
        if current in path:
            return
        path.append(current)
        
        if current == target:
            all_paths.append(list(path))
        elif current in adj:
            for neighbor in adj[current]:
                dfs(neighbor, target, path)
        
        path.pop()
    
    for target_id in target_ids:
        for start_node in start_nodes:
            dfs(start_node, target_id, [])
    
    return all_paths

def format_paths_for_console(paths, id_to_label):
    if not paths:
        return "Пути не найдены."
    
    seen_prefixes = set()
    console_path_strings = []
    
    for path in paths:
        if not path:
            continue
        prefix = tuple(path[:3]) if len(path) >= 3 else tuple(path)
        if prefix not in seen_prefixes:
            seen_prefixes.add(prefix)
            
            labeled_path = [id_to_label.get(node, node) for node in path]
            
            if len(path) > 3:
                p1 = labeled_path[0]
                p2 = labeled_path[1]
                p3 = labeled_path[2]
                console_path_strings.append(f"{p1} -> {p2} -> {p3} ->...")
            else:
                console_path_strings.append(" -> ".join(labeled_path))
    
    return "\n".join(console_path_strings)

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

def build_tree(sbom_file, p_name, p_ver, visual, interactive):
    try:
        with open(sbom_file, 'r', encoding='utf-8') as f:
            data = json.load(f)
    except FileNotFoundError:
        return f"Файл {sbom_file} не найден."
    except json.JSONDecodeError as e:
        return f"Ошибка парсинга JSON: {e}"
    
    id_to_label, app_ids, target_ids = build_package_index(data, p_name, p_ver)
    
    if not target_ids:
        return "Пакет не найден в SBOM. Возможно, это dev-зависимость, используйте параметр --dev."
    
    adj = build_dependency_graph(data)
    all_paths = find_all_paths_to_target(adj, app_ids, target_ids)
    
    if not all_paths:
        return "Пути не найдены."
    
    result_string = format_paths_for_console(all_paths, id_to_label)
    
    if visual and all_paths:
        print(f'\n\ndependency paths:')
        print(f'-----------------')
        print(f'{result_string}\n\n')
        
        G = create_networkx_graph(all_paths, id_to_label)
        
        if interactive: draw.visualize_graph(G, p_name)
        else: simple_visualize_graph(G, p_name)
    
    return result_string
