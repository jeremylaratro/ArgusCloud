# AWSHound Product Demo

## Contents
- `screenshot-graph.png`: Graph tab showing type-colored nodes and severity-colored attack paths.
- `screenshot-environment.png`: Environment tab with object counts and sample objects.
- `screenshot-data.png`: Data Management tab with fetch/upload/report download.

## How to View
Open the images in this folder directly (e.g., double-click in your file explorer or use `open screenshot-graph.png`).

## How the Demo Was Captured
1) Load sample data into Neo4j:
   ```bash
   PYTHONPATH=. ./scripts/load_to_neo4j.py \
     --nodes ui/sample_nodes_expanded.jsonl \
     --edges ui/sample_edges_expanded.jsonl \
     --uri bolt://localhost:7687 \
     --user neo4j \
     --password letmein123
   ```
2) Start API: `PYTHONPATH=. python server/api.py --uri bolt://localhost:7687 --user neo4j --password letmein123 --port 5000`
3) Start UI: `cd ui && python -m http.server 8001`
4) Run screenshot script: `node scripts/screenshot_ui.js`

## Feature Highlights
- Graph: type-based node colors, severity-colored attack edges, resize bar, fullscreen panel, selection details.
- Environment: expandable object details with counts and sample objects.
- Data Management: API fetch, file upload (offline mode), report download.
- Settings: API base, layout, label position, theme; collapsible sidebar with filters and Cypher console.
