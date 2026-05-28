import networkx as nx
import os
from pyvis.network import Network

def visualize_graph(G, p_name):
    if not G.nodes():
        print("Нет узлов для визуализации.")
        return

    net = Network(height="1000px", width="100%", directed=True, bgcolor="#222222", font_color="white")
    
    node_levels = {}
    for node in G.nodes():
        if G.nodes[node].get('is_start'):
            node_levels[node] = 0
    for start_node in [n for n in G.nodes() if G.nodes[n].get('is_start')]:
        lengths = nx.single_source_shortest_path_length(G, start_node)
        for node, dist in lengths.items():
            node_levels[node] = min(node_levels.get(node, float('inf')), dist)

    max_level = max(node_levels.values()) if node_levels else 1
    node_count = len(G.nodes())
    level_sep = max(80, min(200, 1200 // (max_level + 1)))
    node_spacing = max(120, min(300, 2000 // (node_count // (max_level + 1) + 1)))

    net.set_options(f"""
    {{
      "layout": {{
        "hierarchical": {{
          "enabled": true,
          "direction": "UD",
          "levelSeparation": {level_sep},
          "nodeSpacing": {node_spacing},
          "treeSpacing": 200,
          "blockShifting": true,
          "edgeMinimization": true,
          "parentCentralization": true
        }}
      }},
      "physics": {{
        "enabled": false
      }},
      "nodes": {{
        "shape": "box",
        "margin": 8,
        "font": {{ "size": 14 }}
      }},
      "edges": {{
        "smooth": {{
          "type": "cubicBezier",
          "forceDirection": "vertical",
          "roundness": 0.3
        }}
      }}
    }}
    """)

    for node, data in G.nodes(data=True):
        level = node_levels.get(node, 0)
        if data.get('is_start'):
            color = "#97C2FC"  # Светло-синий для корней (start)
        elif data.get('is_sink'):
             color = "#FF6B6B" # Красный для цели (sink)
             level = max_level + 1
        else:
            color = "#84DCC6"  # Бирюзовый для промежуточных

        label = node if len(node) < 35 else node[:32] + "..."

        net.add_node(
            node, 
            label=label, 
            title=node, 
            color=color, 
            size=50,
            borderWidth=2,
            borderWidthSelected=4,
            level=level,
            font={'size': 14, 'face': 'arial', 'color': 'white'}
        )

    for source, target in G.edges():
        net.add_edge(source, target, color="gray", width=1, arrowStrikethrough=False)

    output_filename = f"dependency_graph_{p_name.replace('/', '_')}.html"

    try:
        net.save_graph(output_filename)
        print(f"\nВау!!! Граф сохранен в файл: {output_filename}")

        os.startfile(output_filename)

    except Exception as e:
        print(f"Ошибка при сохранении или открытии файла визуализации: {e}")

