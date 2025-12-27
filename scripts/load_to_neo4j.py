#!/usr/bin/env python
"""
Load awshound JSONL bundle into Neo4j.

Usage:
  python scripts/load_to_neo4j.py --nodes awshound-output/nodes.jsonl --edges awshound-output/edges.jsonl --uri bolt://localhost:7687 --user neo4j --password letmein
"""

import argparse
from pathlib import Path

from awshound.storage import Neo4jLoader, load_jsonl_edges, load_jsonl_nodes


def main() -> None:
    parser = argparse.ArgumentParser(description="Load awshound bundle into Neo4j")
    parser.add_argument("--nodes", required=True, help="Path to nodes.jsonl")
    parser.add_argument("--edges", required=True, help="Path to edges.jsonl")
    parser.add_argument("--uri", default="bolt://localhost:7687", help="Neo4j bolt URI")
    parser.add_argument("--user", default="neo4j", help="Neo4j user")
    parser.add_argument("--password", required=True, help="Neo4j password")
    parser.add_argument("--batch-size", type=int, default=1000, help="Batch size for MERGE operations")
    args = parser.parse_args()

    nodes = load_jsonl_nodes(Path(args.nodes))
    edges = load_jsonl_edges(Path(args.edges))
    loader = Neo4jLoader(args.uri, args.user, args.password, batch_size=args.batch_size)
    loader.load(nodes, edges)
    print(f"Loaded {len(nodes)} nodes and {len(edges)} edges into {args.uri}")


if __name__ == "__main__":
    main()
