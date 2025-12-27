# AWSHound UI with Neo4j API

## Run Neo4j
```bash
sudo docker run -d \
  --name awshound-neo4j \
  -p 7474:7474 -p 7687:7687 \
  -e NEO4J_AUTH=neo4j/letmein123 \
  -v "$(pwd)/neo4j/data":/data \
  -v "$(pwd)/neo4j/logs":/logs \
  neo4j:5
```

## Start API server (pulls from Neo4j)
```bash
PYTHONPATH=. python server/api.py --uri bolt://localhost:7687 --user neo4j --password letmein123 --port 5000
```

Endpoints:
- `GET /health`
- `GET /graph?limit=500` returns `{nodes, edges}`
- `GET /attackpaths?limit=500` returns attack-path edges only
- `POST /query` with `{"cypher": "...", "limit": 200}` for Cypher console

## Use UI with API
1) Start UI server: `cd ui && python -m http.server 8000`
2) Open http://localhost:8000
3) In the UI, set API base to `http://localhost:5000` and click “Fetch from API” (or continue to use local file upload).

## Sample Data
Load sample bundle into Neo4j (optional):
```bash
PYTHONPATH=. ./scripts/load_to_neo4j.py \
  --nodes ui/sample_nodes.jsonl \
  --edges ui/sample_edges.jsonl \
  --uri bolt://localhost:7687 \
  --user neo4j \
  --password letmein123
```
