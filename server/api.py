import argparse
import os
from typing import Any, Dict, List

from flask import Flask, jsonify, request
from flask_cors import CORS
from neo4j import GraphDatabase


def get_driver(uri: str, user: str, password: str):
    return GraphDatabase.driver(uri, auth=(user, password))


def create_app(uri: str, user: str, password: str) -> Flask:
    driver = get_driver(uri, user, password)
    app = Flask(__name__)
    CORS(app)

    @app.after_request
    def add_cors(resp):
        resp.headers["Access-Control-Allow-Origin"] = "*"
        resp.headers["Access-Control-Allow-Headers"] = "Content-Type,Authorization"
        resp.headers["Access-Control-Allow-Methods"] = "GET,POST,OPTIONS"
        return resp

    @app.route("/health")
    def health():
        try:
            with driver.session() as session:
                session.run("RETURN 1").single()
            return jsonify({"status": "ok"})
        except Exception as exc:  # pragma: no cover - network
            return jsonify({"status": "error", "detail": str(exc)}), 500

    @app.route("/graph")
    def graph():
        limit = int(request.args.get("limit", "500"))
        nodes = _query_nodes(driver, limit)
        edges = _query_edges(driver, limit)
        return jsonify({"nodes": nodes, "edges": edges})

    @app.route("/attackpaths")
    def attackpaths():
        limit = int(request.args.get("limit", "500"))
        edges = _query_edges(driver, limit, attack_only=True)
        return jsonify({"edges": edges})

    @app.route("/query", methods=["POST"])
    def query():
        body = request.get_json(force=True) or {}
        cypher = body.get("cypher")
        limit = int(body.get("limit", 200))
        if not cypher:
            return jsonify({"error": "missing cypher"}), 400
        try:
            with driver.session() as session:
                records = session.run(cypher + " LIMIT $limit", limit=limit)
                # Convert records to dicts
                results = [r.data() for r in records]
            return jsonify({"results": results})
        except Exception as exc:  # pragma: no cover - network
            return jsonify({"error": str(exc)}), 500

    return app


def _query_nodes(driver, limit: int) -> List[Dict[str, Any]]:
    cypher = "MATCH (n:Resource) RETURN n.id AS id, n.type AS type, properties(n) AS props LIMIT $limit"
    with driver.session() as session:
        records = session.run(cypher, limit=limit)
        return [{"id": r["id"], "type": r["type"], "properties": r["props"]} for r in records]


def _query_edges(driver, limit: int, attack_only: bool = False) -> List[Dict[str, Any]]:
    cypher = "MATCH (a:Resource)-[r:REL]->(b:Resource) "
    if attack_only:
        cypher += "WHERE r.type = 'AttackPath' "
    cypher += "RETURN a.id AS src, b.id AS dst, r.type AS type, properties(r) AS props LIMIT $limit"
    with driver.session() as session:
        records = session.run(cypher, limit=limit)
        return [{"src": r["src"], "dst": r["dst"], "type": r["type"], "properties": r["props"]} for r in records]


def main():
    parser = argparse.ArgumentParser(description="AWSHound Neo4j API")
    parser.add_argument("--uri", default=os.environ.get("NEO4J_URI", "bolt://localhost:7687"))
    parser.add_argument("--user", default=os.environ.get("NEO4J_USER", "neo4j"))
    parser.add_argument("--password", default=os.environ.get("NEO4J_PASSWORD", "letmein123"))
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=5000)
    args = parser.parse_args()

    app = create_app(args.uri, args.user, args.password)
    app.run(host=args.host, port=args.port)


if __name__ == "__main__":
    main()
