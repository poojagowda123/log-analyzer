
import pandas as pd
import json
from pathlib import Path
import os

# Paths
BASE_DIR = Path(__file__).resolve().parent.parent
LOGS_PATH = BASE_DIR / "Output" / "windows_logs_parsed.csv"
OUTPUT_HTML = BASE_DIR / "Output" / "knowledge_graph.html"
OUTPUT_DIR = BASE_DIR / "Output"

HTML_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <script type="text/javascript" src="https://unpkg.com/vis-network/standalone/umd/vis-network.min.js"></script>
    <style type="text/css">
        body { background-color: #0f172a; color: white; font-family: sans-serif; }
        #mynetwork { width: 100%; height: 750px; border: 1px solid #334155; border-radius: 8px; }
        h2 { text-align: center; color: #38bdf8; }
    </style>
</head>
<body>
    <h2>Security Knowledge Graph</h2>
    <div id="mynetwork"></div>
    <script type="text/javascript">
        var nodes = new vis.DataSet(__NODES__);
        var edges = new vis.DataSet(__EDGES__);

        var container = document.getElementById('mynetwork');
        var data = { nodes: nodes, edges: edges };
        var options = {
            nodes: {
                shape: 'dot',
                size: 16,
                font: { size: 14, color: '#ffffff' },
                borderWidth: 2
            },
            edges: {
                width: 1,
                color: { color: '#475569', highlight: '#38bdf8' },
                smooth: { type: 'continuous' }
            },
            physics: {
                stabilization: false,
                barnesHut: {
                    gravitationalConstant: -8000,
                    springConstant: 0.04,
                    springLength: 95
                }
            }
        };
        var network = new vis.Network(container, data, options);
    </script>
</body>
</html>
"""

def build_graph():
    print("Building Knowledge Graph (Manual HTML)...")
    if not LOGS_PATH.exists():
        print(f"Error: {LOGS_PATH} not found.")
        return

    try:
        df = pd.read_csv(LOGS_PATH)
    except Exception as e:
        print(f"Error reading logs: {e}")
        return

    df_logons = df[df['event_id'].isin([4624, 4625])].copy()
    
    if df_logons.empty:
        print("No logon events found.")
        return

    nodes = []
    edges = []
    node_ids = set()
    edge_ids = set()

    for _, row in df_logons.iterrows():
        user = str(row.get('username', 'Unknown'))
        ip = str(row.get('ip', 'Unknown'))
        event_id = row.get('event_id')
        
        if user == 'Unknown' or ip == 'Unknown':
            continue

        # Add Nodes
        if user not in node_ids:
            nodes.append({
                "id": user, "label": user, "group": "user", 
                "color": "#38bdf8", "title": f"User: {user}"
            })
            node_ids.add(user)
        
        if ip not in node_ids:
            color = "#ef4444" if event_id == 4625 else "#22c55e"
            nodes.append({
                "id": ip, "label": ip, "group": "ip", 
                "color": color, "title": f"IP: {ip}"
            })
            node_ids.add(ip)

        # Add Edge
        edge_key = f"{user}-{ip}"
        if edge_key not in edge_ids:
            edges.append({
                "from": user, "to": ip
            })
            edge_ids.add(edge_key)

    print(f"Nodes: {len(nodes)}, Edges: {len(edges)}")
    
    # Generate HTML
    html = HTML_TEMPLATE.replace("__NODES__", json.dumps(nodes)).replace("__EDGES__", json.dumps(edges))
    
    if not OUTPUT_DIR.exists():
        os.makedirs(OUTPUT_DIR)
        
    with open(OUTPUT_HTML, "w", encoding="utf-8") as f:
        f.write(html)
    
    print(f"Graph saved to {OUTPUT_HTML}")

if __name__ == "__main__":
    build_graph()
