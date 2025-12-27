import json
from pathlib import Path
from typing import Iterator, List

from neo4j import GraphDatabase

from .graph import Edge, Node


def load_jsonl_nodes(path: Path) -> List[Node]:
    with path.open("r", encoding="utf-8") as f:
        return [Node(**json.loads(line)) for line in f]


def load_jsonl_edges(path: Path) -> List[Edge]:
    with path.open("r", encoding="utf-8") as f:
        return [Edge(**json.loads(line)) for line in f]


def stream_jsonl(path: Path) -> Iterator[dict]:
    with path.open("r", encoding="utf-8") as f:
        for line in f:
            yield json.loads(line)


def _chunk(seq, size: int):
    for i in range(0, len(seq), size):
        yield seq[i : i + size]


class Neo4jLoader:
    """Lightweight loader for Neo4j. Uses MERGE to avoid dupes; batches for large graphs."""

    def __init__(self, uri: str, user: str, password: str, batch_size: int = 1000) -> None:
        self.uri = uri
        self.user = user
        self.password = password
        self.batch_size = batch_size

    def load(self, nodes: List[Node], edges: List[Edge]) -> None:
        driver = GraphDatabase.driver(self.uri, auth=(self.user, self.password))
        with driver.session() as session:
            for batch in _chunk(nodes, self.batch_size):
                session.execute_write(self._merge_nodes, batch)
            for batch in _chunk(edges, self.batch_size):
                session.execute_write(self._merge_edges, batch)
        driver.close()

    @staticmethod
    def _merge_nodes(tx, batch: List[Node]) -> None:
        tx.run(
            """
            UNWIND $nodes AS n
            MERGE (node:Resource {id: n.id})
            SET node.type = n.type, node += n.properties
            """,
            nodes=[n.to_dict() for n in batch],
        )

    @staticmethod
    def _merge_edges(tx, batch: List[Edge]) -> None:
        tx.run(
            """
            UNWIND $edges AS e
            MERGE (src:Resource {id: e.src})
            MERGE (dst:Resource {id: e.dst})
            MERGE (src)-[rel:REL {type: e.type, id: e.src + '>' + e.dst + ':' + e.type}]->(dst)
            SET rel += e.properties
            """,
            edges=[e.to_dict() for e in batch],
        )
