# Neo4j Loader Notes

## When to use
- Large AWS environments where client-side/in-memory graph is too heavy.
- Need Cypher queries and Neo4j Browser/BI integration.

## Requirements
- Neo4j 5.x.
- Credentials with write access; bolt URI (e.g., `bolt://localhost:7687` or `neo4j://host:7687`).
- Install dependencies: `pip install -r requirements.txt` (includes `neo4j` driver).

## Loading workflow
1) Collect data: `python -m arguscloud.cli collect --output arguscloud-output`
2) Normalize + rules: `python -m arguscloud.cli normalize --output arguscloud-output`
3) Load into Neo4j (Python snippet):
```python
from arguscloud.storage import load_jsonl_nodes, load_jsonl_edges, Neo4jLoader
from pathlib import Path

nodes = load_jsonl_nodes(Path("arguscloud-output/nodes.jsonl"))
edges = load_jsonl_edges(Path("arguscloud-output/edges.jsonl"))
loader = Neo4jLoader(uri="bolt://localhost:7687", user="neo4j", password="pass", batch_size=1000)
loader.load(nodes, edges)
```

## Notes
- Loader uses MERGE with a generic `Resource` label and `REL` relationship; `type` is stored on nodes and relationships.
- Batch size defaults to 1000; tune for your Neo4j heap and dataset size.
- Edges carry `properties` including `rule`/`description` for attack-path edges. Adjust Cypher as needed for custom indexes/labels.
