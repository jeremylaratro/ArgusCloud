"""CloudHound API server with authentication support."""

from __future__ import annotations

import argparse
import logging
import os
import re
from typing import Any, Dict, List, Optional, Tuple, Union

from flask import Flask, Response, jsonify, request, g
from flask_cors import CORS
from neo4j import GraphDatabase

# Type alias for Flask responses
FlaskResponse = Union[Response, Tuple[Response, int], Tuple[Dict[str, Any], int]]

from .auth import AuthConfig, init_auth, require_auth
from ..plugins import PluginRegistry, discover_plugins, load_plugins
from ..plugins.registry import get_registry

logger = logging.getLogger(__name__)

# Security constants
ALLOWED_ORIGINS = os.environ.get(
    "CLOUDHOUND_CORS_ORIGINS",
    "http://localhost:8080,http://127.0.0.1:8080"
).split(",")

# Cypher query validation - whitelist patterns for safe read-only queries
SAFE_CYPHER_PATTERNS = [
    re.compile(r'^\s*MATCH\s+.*RETURN\s+', re.IGNORECASE | re.DOTALL),
    re.compile(r'^\s*CALL\s+db\.\w+', re.IGNORECASE),
    re.compile(r'^\s*CALL\s+apoc\.\w+', re.IGNORECASE),
]

# Dangerous keywords that should never appear in queries (even in whitelisted patterns)
DANGEROUS_CYPHER_KEYWORDS = re.compile(
    r'\b(DELETE|DETACH|CREATE|MERGE|SET|REMOVE|DROP|LOAD\s+CSV|FOREACH)\b',
    re.IGNORECASE
)

# Profile name validation pattern
PROFILE_NAME_PATTERN = re.compile(r'^[a-zA-Z0-9_\-\.]{1,100}$')

# Constants for query limits
DEFAULT_QUERY_LIMIT = 500
MAX_QUERY_LIMIT = 10000

# Zip bomb protection
MAX_UNCOMPRESSED_SIZE = 500 * 1024 * 1024  # 500MB
MAX_ZIP_FILES = 1000


def validate_cypher_query(query: str) -> bool:
    """Validate that a Cypher query is safe (read-only).

    Uses whitelist pattern matching combined with dangerous keyword blacklist.
    """
    # Remove comments that could be used to bypass checks
    cleaned = re.sub(r'/\*.*?\*/', '', query, flags=re.DOTALL)  # Block comments
    cleaned = re.sub(r'//.*$', '', cleaned, flags=re.MULTILINE)  # Line comments
    cleaned = cleaned.strip()

    # First check for dangerous keywords - these are never allowed
    if DANGEROUS_CYPHER_KEYWORDS.search(cleaned):
        return False

    # Check against whitelist patterns
    for pattern in SAFE_CYPHER_PATTERNS:
        if pattern.match(cleaned):
            return True
    return False


def validate_profile_name(name: str) -> bool:
    """Validate profile name format."""
    return bool(name and PROFILE_NAME_PATTERN.match(name))


def get_validated_limit(default: int = DEFAULT_QUERY_LIMIT, max_limit: int = MAX_QUERY_LIMIT) -> int:
    """Get and validate the limit query parameter."""
    try:
        limit = int(request.args.get("limit", default))
        return max(1, min(limit, max_limit))
    except (ValueError, TypeError):
        return default


def get_validated_json() -> Tuple[Optional[Dict[str, Any]], Optional[FlaskResponse]]:
    """Get and validate JSON request body.

    Returns:
        Tuple of (data, error_response) where error_response is None on success
    """
    if not request.is_json:
        return None, (jsonify({"error": "Content-Type must be application/json"}), 400)
    try:
        data = request.get_json(force=False, silent=False)
        return data or {}, None
    except Exception:
        return None, (jsonify({"error": "Invalid JSON payload"}), 400)


def get_driver(uri: str, user: str, password: str) -> Any:
    """Create Neo4j driver connection."""
    return GraphDatabase.driver(uri, auth=(user, password))


def create_app(
    uri: str,
    user: str,
    password: str,
    auth_config: Optional[AuthConfig] = None
) -> Flask:
    """Create and configure the CloudHound API Flask application.

    Args:
        uri: Neo4j connection URI
        user: Neo4j username
        password: Neo4j password
        auth_config: Optional authentication configuration

    Returns:
        Configured Flask application
    """
    driver = get_driver(uri, user, password)
    app = Flask(__name__)
    CORS(app)

    # Initialize authentication
    init_auth(app, auth_config)

    # Initialize plugin system
    registry = get_registry()
    discovered = registry.discover()
    loaded = registry.load_all()
    logger.info(f"Plugins: discovered={len(discovered)}, loaded={loaded}")

    # Register plugin routes
    registry.register_routes(app)

    @app.after_request
    def add_cors(resp):
        origin = request.headers.get("Origin", "")
        # Use specific origin instead of wildcard for better security
        if origin in ALLOWED_ORIGINS:
            resp.headers["Access-Control-Allow-Origin"] = origin
        elif ALLOWED_ORIGINS:
            # Default to first allowed origin for non-browser requests
            resp.headers["Access-Control-Allow-Origin"] = ALLOWED_ORIGINS[0]
        resp.headers["Access-Control-Allow-Headers"] = "Content-Type,Authorization,X-API-Key"
        resp.headers["Access-Control-Allow-Methods"] = "GET,POST,OPTIONS,DELETE,PATCH"
        resp.headers["Access-Control-Allow-Credentials"] = "true"
        return resp

    @app.route("/health")
    def health() -> FlaskResponse:
        """Health check endpoint (unauthenticated).

        Returns status of all system components.
        """
        health_status = {
            "status": "ok",
            "checks": {},
            "version": "0.2.0"
        }

        # Check Neo4j connectivity
        try:
            with driver.session() as session:
                session.run("RETURN 1").single()
            health_status["checks"]["neo4j"] = "ok"
        except Exception:
            health_status["checks"]["neo4j"] = "error"
            health_status["status"] = "degraded"

        # Check plugin system
        try:
            plugin_count = registry.plugin_count
            health_status["checks"]["plugins"] = f"ok ({plugin_count} loaded)"
        except Exception:
            health_status["checks"]["plugins"] = "error"

        # Return appropriate status code
        if health_status["status"] == "ok":
            return jsonify(health_status)
        else:
            return jsonify(health_status), 503

    @app.route("/plugins")
    def list_plugins() -> FlaskResponse:
        """List installed plugins (unauthenticated)."""
        plugins = registry.get_plugin_info()
        errors = registry.load_errors
        return jsonify({
            "plugins": plugins,
            "count": len(plugins),
            "errors": errors
        })

    @app.route("/graph")
    @require_auth(allow_read=True)
    def graph() -> FlaskResponse:
        """Get graph nodes and edges."""
        limit = get_validated_limit()
        provider = request.args.get("provider")  # Optional filter by cloud provider
        node_type = request.args.get("type")  # Optional filter by node type

        nodes = _query_nodes(driver, limit, provider=provider, node_type=node_type)
        edges = _query_edges(driver, limit, provider=provider)
        return jsonify({
            "nodes": nodes,
            "edges": edges,
            "meta": {
                "total_nodes": len(nodes),
                "total_edges": len(edges),
                "limit": limit
            }
        })

    @app.route("/attackpaths")
    @require_auth(allow_read=True)
    def attackpaths() -> FlaskResponse:
        """Get attack path edges."""
        limit = get_validated_limit()
        severity = request.args.get("severity")  # Optional filter by severity
        provider = request.args.get("provider")  # Optional filter by provider

        edges = _query_attack_paths(driver, limit, severity=severity, provider=provider)
        return jsonify({
            "edges": edges,
            "meta": {
                "total": len(edges),
                "limit": limit
            }
        })

    @app.route("/findings")
    @require_auth(allow_read=True)
    def findings() -> FlaskResponse:
        """Get security findings summary."""
        edges = _query_attack_paths(driver, limit=10000)

        # Group by severity
        by_severity: Dict[str, List] = {"critical": [], "high": [], "medium": [], "low": []}
        for edge in edges:
            sev = edge.get("properties", {}).get("severity", "medium")
            if sev in by_severity:
                by_severity[sev].append(edge)

        # Group by rule
        by_rule: Dict[str, int] = {}
        for edge in edges:
            rule = edge.get("properties", {}).get("rule", "unknown")
            by_rule[rule] = by_rule.get(rule, 0) + 1

        return jsonify({
            "total": len(edges),
            "by_severity": {k: len(v) for k, v in by_severity.items()},
            "by_rule": by_rule,
            "critical_findings": by_severity["critical"][:20],
            "high_findings": by_severity["high"][:20],
        })

    @app.route("/resources")
    @require_auth(allow_read=True)
    def resources() -> FlaskResponse:
        """Get resource inventory."""
        provider = request.args.get("provider")
        nodes = _query_nodes(driver, limit=10000, provider=provider)

        # Group by type
        by_type: Dict[str, int] = {}
        for node in nodes:
            ntype = node.get("type") or "unknown"
            by_type[ntype] = by_type.get(ntype, 0) + 1

        return jsonify({
            "total": len(nodes),
            "by_type": by_type,
        })

    @app.route("/query", methods=["POST"])
    @require_auth
    def query() -> FlaskResponse:
        """Execute a custom Cypher query."""
        body, error = get_validated_json()
        if error:
            return error

        cypher = body.get("cypher")
        try:
            limit = int(body.get("limit", 200))
            limit = max(1, min(limit, MAX_QUERY_LIMIT))
        except (ValueError, TypeError):
            limit = 200

        if not cypher:
            return jsonify({"error": "missing cypher"}), 400

        # Whitelist-based query validation (more secure than blacklist)
        if not validate_cypher_query(cypher):
            return jsonify({
                "error": "Query not allowed",
                "message": "Only MATCH...RETURN and CALL db.*/apoc.* queries are permitted"
            }), 403

        try:
            with driver.session() as session:
                # Append LIMIT if not present (use parameterized query)
                cypher_upper = cypher.upper()
                if "LIMIT" not in cypher_upper:
                    cypher = f"{cypher} LIMIT $limit"
                    records = session.run(cypher, limit=limit)
                else:
                    records = session.run(cypher)
                results = [r.data() for r in records]
            return jsonify({"results": results, "count": len(results)})
        except Exception as exc:
            logger.warning(f"Cypher query error: {type(exc).__name__}")
            return jsonify({"error": "Query execution failed"}), 500

    @app.route("/export/<format>")
    @require_auth(allow_read=True)
    def export(format: str) -> FlaskResponse:
        """Export findings in various formats."""
        from cloudhound.core.graph import GraphData, Node, Edge
        from cloudhound.exporters import JSONExporter, SARIFExporter, HTMLExporter

        # Fetch all data
        nodes_data = _query_nodes(driver, limit=10000)
        edges_data = _query_edges(driver, limit=10000)
        attack_paths = _query_attack_paths(driver, limit=10000)

        # Convert to graph objects
        nodes = [Node(id=n["id"], type=n["type"], properties=n.get("properties", {}))
                 for n in nodes_data]
        edges = [Edge(src=e["src"], dst=e["dst"], type=e["type"], properties=e.get("properties", {}))
                 for e in attack_paths]

        graph = GraphData(nodes=nodes, edges=edges)

        if format == "json":
            exporter = JSONExporter(graph, edges)
            content = exporter.export()
            return app.response_class(content, mimetype="application/json")

        elif format == "sarif":
            exporter = SARIFExporter(graph, edges)
            content = exporter.export()
            return app.response_class(content, mimetype="application/json")

        elif format == "html":
            exporter = HTMLExporter(graph, edges)
            content = exporter.export()
            return app.response_class(content, mimetype="text/html")

        else:
            return jsonify({"error": f"Unknown format: {format}"}), 400

    # ============ Profile Management Endpoints ============

    @app.route("/profiles")
    @require_auth(allow_read=True)
    def list_profiles() -> FlaskResponse:
        """List all saved profiles."""
        cypher = """
        MATCH (p:Profile)
        RETURN p.name AS name, p.created_at AS created_at, p.updated_at AS updated_at,
               p.node_count AS node_count, p.edge_count AS edge_count
        ORDER BY p.updated_at DESC
        """
        with driver.session() as session:
            records = session.run(cypher)
            profiles = [
                {
                    "name": r["name"],
                    "created_at": r["created_at"],
                    "updated_at": r["updated_at"],
                    "node_count": r["node_count"],
                    "edge_count": r["edge_count"]
                }
                for r in records
            ]
        return jsonify({"profiles": profiles})

    def _unflatten_props(props: Dict[str, Any]) -> Dict[str, Any]:
        """Attempt to parse JSON strings back to objects."""
        import json
        result = {}
        exclude_keys = {"profile", "id", "type", "provider"}
        for key, value in props.items():
            if key in exclude_keys:
                continue
            if isinstance(value, str) and len(value) > 0 and value[0] in '[{':
                try:
                    result[key] = json.loads(value)
                except json.JSONDecodeError:
                    result[key] = value
            else:
                result[key] = value
        return result

    @app.route("/profiles/<name>")
    @require_auth(allow_read=True)
    def get_profile(name: str) -> FlaskResponse:
        """Get a specific profile's data."""
        # Get nodes for this profile
        nodes_cypher = """
        MATCH (n:Resource {profile: $name})
        RETURN n.id AS id, n.type AS type, n.provider AS provider, properties(n) AS props
        """
        # Get edges for this profile
        edges_cypher = """
        MATCH (a:Resource {profile: $name})-[r:REL]->(b)
        RETURN a.id AS src, b.id AS dst, r.type AS type, properties(r) AS props
        """

        with driver.session() as session:
            node_records = session.run(nodes_cypher, name=name)
            nodes = [
                {
                    "id": r["id"],
                    "type": r["type"],
                    "provider": r["provider"],
                    "properties": _unflatten_props(dict(r["props"]))
                }
                for r in node_records
            ]

            edge_records = session.run(edges_cypher, name=name)
            edges = [
                {
                    "src": r["src"],
                    "dst": r["dst"],
                    "type": r["type"],
                    "properties": _unflatten_props(dict(r["props"]))
                }
                for r in edge_records
            ]

        return jsonify({
            "name": name,
            "nodes": nodes,
            "edges": edges,
            "meta": {
                "node_count": len(nodes),
                "edge_count": len(edges)
            }
        })

    def _flatten_props(props: Dict[str, Any]) -> Dict[str, Any]:
        """Flatten nested objects to JSON strings for Neo4j storage."""
        import json
        result = {}
        for key, value in props.items():
            if value is None:
                continue
            elif isinstance(value, (dict, list)):
                # Serialize complex types to JSON string
                result[key] = json.dumps(value)
            elif isinstance(value, (str, int, float, bool)):
                result[key] = value
            else:
                # Convert other types to string
                result[key] = str(value)
        return result

    @app.route("/profiles", methods=["POST"])
    @require_auth
    def save_profile() -> FlaskResponse:
        """Save nodes and edges to a named profile."""
        body, error = get_validated_json()
        if error:
            return error

        name = body.get("name")
        nodes = body.get("nodes", [])
        edges = body.get("edges", [])
        mode = body.get("mode", "create")  # create, overwrite, merge

        if not name:
            return jsonify({"error": "Profile name is required"}), 400

        if not validate_profile_name(name):
            return jsonify({
                "error": "Invalid profile name",
                "message": "Profile name must be 1-100 characters, alphanumeric with _ - . allowed"
            }), 400

        if not nodes and not edges:
            return jsonify({"error": "No data to save"}), 400

        try:
            with driver.session() as session:
                # Check if profile exists
                exists = session.run(
                    "MATCH (p:Profile {name: $name}) RETURN p.name AS name",
                    name=name
                ).single()

                if exists and mode == "create":
                    return jsonify({
                        "error": "Profile already exists",
                        "exists": True,
                        "message": f"Profile '{name}' already exists. Choose overwrite or merge."
                    }), 409

                if mode == "overwrite" or (mode == "create" and not exists):
                    # Delete existing profile data if overwriting
                    if exists:
                        session.run("""
                            MATCH (n:Resource {profile: $name})
                            DETACH DELETE n
                        """, name=name)
                        session.run("MATCH (p:Profile {name: $name}) DELETE p", name=name)

                # Create/update profile metadata
                from datetime import datetime
                now = datetime.utcnow().isoformat()

                if mode == "merge" and exists:
                    session.run("""
                        MATCH (p:Profile {name: $name})
                        SET p.updated_at = $now
                    """, name=name, now=now)
                else:
                    session.run("""
                        MERGE (p:Profile {name: $name})
                        ON CREATE SET p.created_at = $now, p.updated_at = $now
                        ON MATCH SET p.updated_at = $now
                    """, name=name, now=now)

                # Insert nodes
                for node in nodes:
                    node_props = _flatten_props(node.get("properties", {}))
                    node_props["id"] = node["id"]
                    node_props["type"] = node.get("type") or "Unknown"
                    node_props["provider"] = node.get("provider") or "unknown"
                    node_props["profile"] = name

                    session.run("""
                        MERGE (n:Resource {id: $id, profile: $profile})
                        SET n += $props
                    """, id=node["id"], profile=name, props=node_props)

                # Insert edges
                for edge in edges:
                    edge_props = _flatten_props(edge.get("properties", {}))
                    edge_props["type"] = edge.get("type") or "REL"
                    edge_props["profile"] = name

                    # Create source node if it doesn't exist
                    session.run("""
                        MERGE (src:Resource {id: $src_id, profile: $profile})
                        ON CREATE SET src.type = 'External', src.provider = 'external'
                    """, src_id=edge["src"], profile=name)

                    # Create target node if it doesn't exist (for external references like "internet")
                    session.run("""
                        MERGE (dst:Resource {id: $dst_id, profile: $profile})
                        ON CREATE SET dst.type = 'External', dst.provider = 'external'
                    """, dst_id=edge["dst"], profile=name)

                    session.run("""
                        MATCH (a:Resource {id: $src, profile: $profile})
                        MATCH (b:Resource {id: $dst, profile: $profile})
                        MERGE (a)-[r:REL]->(b)
                        SET r += $props
                    """, src=edge["src"], dst=edge["dst"], profile=name, props=edge_props)

                # Update profile counts
                session.run("""
                    MATCH (p:Profile {name: $name})
                    SET p.node_count = $node_count, p.edge_count = $edge_count
                """, name=name, node_count=len(nodes), edge_count=len(edges))

            return jsonify({
                "success": True,
                "name": name,
                "node_count": len(nodes),
                "edge_count": len(edges),
                "mode": mode
            })
        except Exception as e:
            return jsonify({"error": str(e)}), 500

    @app.route("/profiles/<name>", methods=["DELETE"])
    @require_auth
    def delete_profile(name: str) -> FlaskResponse:
        """Delete a profile and all its data."""
        with driver.session() as session:
            # Check if profile exists
            exists = session.run(
                "MATCH (p:Profile {name: $name}) RETURN p.name",
                name=name
            ).single()

            if not exists:
                return jsonify({"error": "Profile not found"}), 404

            # Delete all nodes and edges for this profile
            session.run("""
                MATCH (n:Resource {profile: $name})
                DETACH DELETE n
            """, name=name)

            # Delete profile metadata
            session.run("MATCH (p:Profile {name: $name}) DELETE p", name=name)

        return jsonify({"success": True, "deleted": name})

    @app.route("/profiles/<name>/rename", methods=["POST"])
    @require_auth
    def rename_profile(name: str) -> FlaskResponse:
        """Rename a profile."""
        body, error = get_validated_json()
        if error:
            return error

        new_name = body.get("new_name")

        if not new_name:
            return jsonify({"error": "New name is required"}), 400

        if not validate_profile_name(new_name):
            return jsonify({
                "error": "Invalid profile name",
                "message": "Profile name must be 1-100 characters, alphanumeric with _ - . allowed"
            }), 400

        with driver.session() as session:
            # Check if source profile exists
            exists = session.run(
                "MATCH (p:Profile {name: $name}) RETURN p.name",
                name=name
            ).single()

            if not exists:
                return jsonify({"error": "Profile not found"}), 404

            # Check if target name already exists
            target_exists = session.run(
                "MATCH (p:Profile {name: $name}) RETURN p.name",
                name=new_name
            ).single()

            if target_exists:
                return jsonify({"error": f"Profile '{new_name}' already exists"}), 409

            # Update profile name
            session.run("""
                MATCH (p:Profile {name: $old_name})
                SET p.name = $new_name
            """, old_name=name, new_name=new_name)

            # Update all nodes
            session.run("""
                MATCH (n:Resource {profile: $old_name})
                SET n.profile = $new_name
            """, old_name=name, new_name=new_name)

        return jsonify({"success": True, "old_name": name, "new_name": new_name})

    # ============ Collection Endpoints ============

    @app.route("/collect/aws", methods=["POST"])
    @require_auth
    def start_aws_collection() -> FlaskResponse:
        """Start an AWS collection job with provided credentials."""
        import threading
        from .collect import (
            get_job_manager, run_collection_job, CollectionJob, JobStatus
        )
        from ..collectors.session import AWSCredentials, validate_credentials

        body, error = get_validated_json()
        if error:
            return error

        # Extract credentials
        access_key = body.get("access_key")
        secret_key = body.get("secret_key")
        session_token = body.get("session_token")
        region = body.get("region")
        services = body.get("services")
        profile_name = body.get("profile_name")

        if not access_key or not secret_key:
            return jsonify({"error": "access_key and secret_key are required"}), 400

        # Default services if not specified
        if not services:
            services = [
                "iam", "iam-roles", "iam-users", "iam-policies",
                "s3", "ec2", "lambda", "kms", "vpc"
            ]

        try:
            # Create credentials object (will validate format)
            credentials = AWSCredentials(
                access_key=access_key,
                secret_key=secret_key,
                session_token=session_token,
                region=region
            )
        except ValueError as e:
            return jsonify({"error": str(e)}), 400

        # Create job
        job_manager = get_job_manager()
        job = job_manager.create_job(services)

        # Start collection in background thread
        thread = threading.Thread(
            target=run_collection_job,
            args=(job, credentials, services, driver, profile_name),
            daemon=True
        )
        thread.start()

        return jsonify({
            "job_id": job.id,
            "status": job.status.value,
            "message": "Collection started"
        }), 202

    @app.route("/collect/<job_id>")
    @require_auth(allow_read=True)
    def get_collection_status(job_id: str) -> FlaskResponse:
        """Get status of a collection job."""
        from .collect import get_job_manager

        job_manager = get_job_manager()
        job = job_manager.get_job(job_id)

        if not job:
            return jsonify({"error": "Job not found"}), 404

        return jsonify(job.to_dict())

    @app.route("/collect/<job_id>/cancel", methods=["POST"])
    @require_auth
    def cancel_collection(job_id: str) -> FlaskResponse:
        """Cancel a running collection job."""
        from .collect import get_job_manager

        job_manager = get_job_manager()
        if job_manager.cancel_job(job_id):
            return jsonify({"success": True, "message": "Job cancelled"})
        return jsonify({"error": "Job not found or already completed"}), 404

    @app.route("/collect/jobs")
    @require_auth(allow_read=True)
    def list_collection_jobs() -> FlaskResponse:
        """List recent collection jobs."""
        from .collect import get_job_manager

        job_manager = get_job_manager()
        jobs = job_manager.list_jobs()

        return jsonify({
            "jobs": [j.to_dict() for j in jobs],
            "count": len(jobs)
        })

    # ============ Bulk Upload Endpoints ============

    @app.route("/upload", methods=["POST"])
    @require_auth
    def upload_files() -> FlaskResponse:
        """Handle bulk file uploads (ZIP or individual JSONL files)."""
        import io
        import threading
        import zipfile
        from .uploads import (
            get_upload_manager, process_upload_files
        )

        upload_manager = get_upload_manager()
        files_data: Dict[str, bytes] = {}

        # Handle multipart file uploads
        if not request.files:
            return jsonify({"error": "No files uploaded"}), 400

        for key, file in request.files.items():
            filename = file.filename
            if not filename:
                continue

            content = file.read()

            # If it's a ZIP file, extract its contents
            if filename.lower().endswith('.zip'):
                try:
                    with zipfile.ZipFile(io.BytesIO(content)) as zf:
                        # Zip bomb protection: check total uncompressed size and file count
                        total_size = sum(f.file_size for f in zf.infolist())
                        file_count = len(zf.namelist())

                        if total_size > MAX_UNCOMPRESSED_SIZE:
                            return jsonify({
                                "error": "Archive too large",
                                "message": f"Uncompressed size ({total_size // (1024*1024)}MB) exceeds limit ({MAX_UNCOMPRESSED_SIZE // (1024*1024)}MB)"
                            }), 400

                        if file_count > MAX_ZIP_FILES:
                            return jsonify({
                                "error": "Too many files in archive",
                                "message": f"Archive contains {file_count} files, max allowed is {MAX_ZIP_FILES}"
                            }), 400

                        for zip_name in zf.namelist():
                            # Skip directories and hidden files
                            if zip_name.endswith('/') or zip_name.startswith('__'):
                                continue
                            if zip_name.lower().endswith('.jsonl'):
                                files_data[zip_name] = zf.read(zip_name)
                except zipfile.BadZipFile:
                    return jsonify({"error": f"Invalid ZIP file: {filename}"}), 400
            elif filename.lower().endswith('.jsonl'):
                files_data[filename] = content

        if not files_data:
            return jsonify({
                "error": "No valid JSONL files found",
                "message": "Upload .jsonl files or a .zip containing them"
            }), 400

        # Count file groups (profiles)
        from .uploads import group_files_by_profile
        groups = group_files_by_profile(files_data)
        total_groups = len(groups)

        # Create upload job
        job = upload_manager.create_job(total_files=total_groups)

        # Process in background thread
        thread = threading.Thread(
            target=process_upload_files,
            args=(job, files_data, driver),
            daemon=True
        )
        thread.start()

        return jsonify({
            "job_id": job.id,
            "status": job.status.value,
            "total_files": len(files_data),
            "total_profiles": total_groups,
            "message": "Upload processing started"
        }), 202

    @app.route("/upload/<job_id>")
    @require_auth(allow_read=True)
    def get_upload_status(job_id: str) -> FlaskResponse:
        """Get status of an upload job."""
        from .uploads import get_upload_manager

        upload_manager = get_upload_manager()
        job = upload_manager.get_job(job_id)

        if not job:
            return jsonify({"error": "Job not found"}), 404

        return jsonify(job.to_dict())

    @app.route("/upload/jobs")
    @require_auth(allow_read=True)
    def list_upload_jobs() -> FlaskResponse:
        """List recent upload jobs."""
        from .uploads import get_upload_manager

        upload_manager = get_upload_manager()
        jobs = upload_manager.list_jobs()

        return jsonify({
            "jobs": [j.to_dict() for j in jobs],
            "count": len(jobs)
        })

    return app


def _query_nodes(
    driver,
    limit: int,
    provider: Optional[str] = None,
    node_type: Optional[str] = None
) -> List[Dict[str, Any]]:
    """Query nodes from Neo4j."""
    cypher = "MATCH (n:Resource) "
    params: Dict[str, Any] = {"limit": limit}

    conditions = []
    if provider:
        conditions.append("n.provider = $provider")
        params["provider"] = provider
    if node_type:
        conditions.append("n.type = $type")
        params["type"] = node_type

    if conditions:
        cypher += "WHERE " + " AND ".join(conditions) + " "

    cypher += "RETURN n.id AS id, n.type AS type, n.provider AS provider, properties(n) AS props LIMIT $limit"

    with driver.session() as session:
        records = session.run(cypher, **params)
        return [
            {
                "id": r["id"],
                "type": r["type"],
                "provider": r["provider"],
                "properties": r["props"]
            }
            for r in records
        ]


def _query_edges(
    driver,
    limit: int,
    provider: Optional[str] = None
) -> List[Dict[str, Any]]:
    """Query edges from Neo4j."""
    cypher = "MATCH (a:Resource)-[r:REL]->(b:Resource) "
    params: Dict[str, Any] = {"limit": limit}

    if provider:
        cypher += "WHERE a.provider = $provider "
        params["provider"] = provider

    cypher += "RETURN a.id AS src, b.id AS dst, r.type AS type, properties(r) AS props LIMIT $limit"

    with driver.session() as session:
        records = session.run(cypher, **params)
        return [
            {
                "src": r["src"],
                "dst": r["dst"],
                "type": r["type"],
                "properties": r["props"]
            }
            for r in records
        ]


def _query_attack_paths(
    driver,
    limit: int,
    severity: Optional[str] = None,
    provider: Optional[str] = None
) -> List[Dict[str, Any]]:
    """Query attack path edges from Neo4j."""
    cypher = "MATCH (a:Resource)-[r:REL]->(b:Resource) WHERE r.type = 'AttackPath' "
    params: Dict[str, Any] = {"limit": limit}

    if severity:
        cypher += "AND r.severity = $severity "
        params["severity"] = severity
    if provider:
        cypher += "AND a.provider = $provider "
        params["provider"] = provider

    cypher += "RETURN a.id AS src, b.id AS dst, r.type AS type, properties(r) AS props ORDER BY "
    cypher += "CASE r.severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 ELSE 3 END "
    cypher += "LIMIT $limit"

    with driver.session() as session:
        records = session.run(cypher, **params)
        return [
            {
                "src": r["src"],
                "dst": r["dst"],
                "type": r["type"],
                "properties": r["props"]
            }
            for r in records
        ]


def main() -> None:
    """Run the CloudHound API server."""
    parser = argparse.ArgumentParser(description="CloudHound API Server")
    parser.add_argument("--uri", default=os.environ.get("NEO4J_URI", "bolt://localhost:7687"))
    parser.add_argument("--user", default=os.environ.get("NEO4J_USER", "neo4j"))
    parser.add_argument("--password", default=os.environ.get("NEO4J_PASSWORD", "letmein123"))
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=5000)
    parser.add_argument("--no-auth", action="store_true", help="Disable authentication")
    args = parser.parse_args()

    auth_config = None
    if args.no_auth:
        auth_config = AuthConfig(enabled=False)

    app = create_app(args.uri, args.user, args.password, auth_config)
    print(f"CloudHound API starting on http://{args.host}:{args.port}")
    app.run(host=args.host, port=args.port)


if __name__ == "__main__":
    main()
