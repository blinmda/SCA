from collections import defaultdict
import json

def build_tree(sbom_file, p_name, p_ver):
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
    
    return all_paths, id_to_label

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