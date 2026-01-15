"""ArgusCloud CLI - Multi-cloud security graph analytics.

This CLI provides commands for:
- Collecting cloud resource data from AWS, GCP, Azure
- Normalizing data into a unified graph format
- Running security rules to detect attack paths
- Exporting findings to various formats
- Starting the API server
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import List, Optional

from arguscloud.core.graph import CloudProvider


# Default services to collect for each provider
AWS_SERVICES = [
    "sts", "org", "iam", "iam-roles", "iam-users", "iam-policies",
    "cloudtrail", "guardduty", "s3", "kms", "vpc", "ec2", "ec2-images",
    "eks", "ecr", "lambda", "cloudformation", "codebuild", "secretsmanager",
    "ssm-parameters", "sns", "sqs", "securityhub", "detective", "config",
    "sso", "rds", "codepipeline", "cloudwatch", "waf", "shield", "fms",
]

GCP_SERVICES = [
    "iam", "compute", "storage", "gke", "cloudrun", "functions",
    "secretmanager", "kms", "logging", "monitoring",
]

AZURE_SERVICES = [
    "iam", "compute", "storage", "aks", "keyvault", "functions",
    "sql", "monitor", "security",
]


def parse_args(args: Optional[List[str]] = None) -> argparse.Namespace:
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        prog="arguscloud",
        description="ArgusCloud - Multi-cloud security graph analytics",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Collect AWS data
  arguscloud collect --provider aws --profile myprofile

  # Normalize collected data
  arguscloud normalize --input ./arguscloud-output

  # Run security rules
  arguscloud analyze --input ./arguscloud-output

  # Export findings
  arguscloud export --format sarif --output findings.sarif

  # Start API server
  arguscloud serve --port 5000
        """
    )

    parser.add_argument(
        "--version",
        action="version",
        version="%(prog)s 0.2.0"
    )

    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # Collect command
    collect_parser = subparsers.add_parser("collect", help="Collect cloud resource data")
    collect_parser.add_argument(
        "--provider", "-p",
        choices=["aws", "gcp", "azure"],
        default="aws",
        help="Cloud provider to collect from (default: aws)"
    )
    collect_parser.add_argument(
        "--output", "-o",
        default="arguscloud-output",
        help="Output directory for collected data (default: arguscloud-output)"
    )
    collect_parser.add_argument(
        "--profile",
        help="Cloud provider profile/credentials name"
    )
    collect_parser.add_argument(
        "--region",
        help="Region override"
    )
    collect_parser.add_argument(
        "--services",
        nargs="+",
        help="Specific services to collect (default: all supported)"
    )
    collect_parser.add_argument(
        "--mode",
        choices=["fast", "full", "stealth"],
        default="fast",
        help="Collection mode (default: fast)"
    )

    # Normalize command
    normalize_parser = subparsers.add_parser("normalize", help="Normalize collected data to graph format")
    normalize_parser.add_argument(
        "--input", "-i",
        default="arguscloud-output",
        help="Input directory with collected data"
    )
    normalize_parser.add_argument(
        "--output", "-o",
        help="Output directory (default: same as input)"
    )

    # Analyze command
    analyze_parser = subparsers.add_parser("analyze", help="Run security rules on normalized data")
    analyze_parser.add_argument(
        "--input", "-i",
        default="arguscloud-output",
        help="Input directory with normalized data"
    )
    analyze_parser.add_argument(
        "--rules",
        nargs="+",
        help="Specific rule IDs to run (default: all)"
    )
    analyze_parser.add_argument(
        "--severity",
        choices=["critical", "high", "medium", "low"],
        help="Minimum severity to report"
    )

    # Export command
    export_parser = subparsers.add_parser("export", help="Export findings to various formats")
    export_parser.add_argument(
        "--input", "-i",
        default="arguscloud-output",
        help="Input directory with analysis data"
    )
    export_parser.add_argument(
        "--format", "-f",
        choices=["json", "sarif", "html"],
        default="json",
        help="Export format (default: json)"
    )
    export_parser.add_argument(
        "--output", "-o",
        help="Output file path"
    )

    # Serve command
    serve_parser = subparsers.add_parser("serve", help="Start the API server")
    serve_parser.add_argument(
        "--host",
        default="0.0.0.0",
        help="Host to bind to (default: 0.0.0.0)"
    )
    serve_parser.add_argument(
        "--port", "-p",
        type=int,
        default=5000,
        help="Port to listen on (default: 5000)"
    )
    serve_parser.add_argument(
        "--neo4j-uri",
        default="bolt://localhost:7687",
        help="Neo4j connection URI"
    )
    serve_parser.add_argument(
        "--neo4j-user",
        default="neo4j",
        help="Neo4j username"
    )
    serve_parser.add_argument(
        "--neo4j-password",
        default="letmein123",
        help="Neo4j password"
    )
    serve_parser.add_argument(
        "--no-auth",
        action="store_true",
        help="Disable API authentication"
    )

    # Import command
    import_parser = subparsers.add_parser("import", help="Import data into Neo4j")
    import_parser.add_argument(
        "--input", "-i",
        default="arguscloud-output",
        help="Input directory with normalized data"
    )
    import_parser.add_argument(
        "--neo4j-uri",
        default="bolt://localhost:7687",
        help="Neo4j connection URI"
    )
    import_parser.add_argument(
        "--neo4j-user",
        default="neo4j",
        help="Neo4j username"
    )
    import_parser.add_argument(
        "--neo4j-password",
        default="letmein123",
        help="Neo4j password"
    )
    import_parser.add_argument(
        "--clear",
        action="store_true",
        help="Clear existing data before import"
    )

    # Generate API key command
    keygen_parser = subparsers.add_parser("keygen", help="Generate a new API key")
    keygen_parser.add_argument(
        "--prefix",
        default="ch",
        help="API key prefix (default: ch)"
    )

    return parser.parse_args(args)


def cmd_collect(args: argparse.Namespace) -> int:
    """Execute the collect command."""
    provider = CloudProvider(args.provider)

    # Get default services for provider
    if args.services:
        services = args.services
    elif provider == CloudProvider.AWS:
        services = AWS_SERVICES
    elif provider == CloudProvider.GCP:
        services = GCP_SERVICES
    elif provider == CloudProvider.AZURE:
        services = AZURE_SERVICES
    else:
        services = []

    print(f"Collecting data from {provider.value}...")
    print(f"Services: {', '.join(services)}")
    print(f"Output: {args.output}")

    if provider == CloudProvider.AWS:
        # Use existing awshound collector
        from awshound import auth
        from awshound.collector import collect_services
        from awshound.manifest import Manifest
        from awshound.modes import RunMode
        from awshound.bundle import write_jsonl, write_manifest

        session, caller = auth.resolve_session(profile=args.profile, region=args.region)
        manifest = Manifest.new(
            mode=RunMode(args.mode.lower()),
            caller_arn=caller.arn,
            account_id=caller.account,
            partition=caller.partition,
            region=caller.resolved_region,
            profile=args.profile or "default",
        )

        outputs = collect_services(session, services=services, manifest=manifest, mode=manifest.mode)
        output_dir = Path(args.output)
        output_dir.mkdir(parents=True, exist_ok=True)

        for svc, records in outputs.items():
            write_jsonl(records, output_dir / f"{svc}.jsonl")

        manifest_path = write_manifest(manifest, output_dir)
        print(json.dumps({"manifest": str(manifest_path), "services": list(outputs.keys())}, indent=2))

    elif provider == CloudProvider.GCP:
        print("GCP collection not yet implemented. Coming soon!")
        return 1

    elif provider == CloudProvider.AZURE:
        print("Azure collection not yet implemented. Coming soon!")
        return 1

    return 0


def cmd_normalize(args: argparse.Namespace) -> int:
    """Execute the normalize command."""
    from awshound import normalize
    from awshound.bundle import write_jsonl

    input_dir = Path(args.input)
    output_dir = Path(args.output) if args.output else input_dir

    print(f"Normalizing data from {input_dir}...")

    # Load raw service data
    raw: dict = {}
    for path in input_dir.glob("*.jsonl"):
        svc = path.stem
        if svc in ("nodes", "edges"):
            continue
        with path.open("r", encoding="utf-8") as f:
            raw[svc] = [json.loads(line) for line in f]

    if not raw:
        print("No service data found to normalize")
        return 1

    nodes, edges = normalize.normalize(raw)

    output_dir.mkdir(parents=True, exist_ok=True)
    write_jsonl((n.to_dict() for n in nodes), output_dir / "nodes.jsonl")
    write_jsonl((e.to_dict() for e in edges), output_dir / "edges.jsonl")

    print(json.dumps({
        "normalized_nodes": len(nodes),
        "normalized_edges": len(edges),
        "output": str(output_dir)
    }, indent=2))

    return 0


def cmd_analyze(args: argparse.Namespace) -> int:
    """Execute the analyze command."""
    from awshound import rules
    from awshound.bundle import write_jsonl
    from arguscloud.core.graph import Node, Edge

    input_dir = Path(args.input)

    print(f"Analyzing data from {input_dir}...")

    # Load normalized data
    nodes_path = input_dir / "nodes.jsonl"
    edges_path = input_dir / "edges.jsonl"

    if not nodes_path.exists() or not edges_path.exists():
        print("Normalized data not found. Run 'arguscloud normalize' first.")
        return 1

    with nodes_path.open("r", encoding="utf-8") as f:
        nodes = [Node.from_dict(json.loads(line)) for line in f]

    with edges_path.open("r", encoding="utf-8") as f:
        edges = [Edge.from_dict(json.loads(line)) for line in f]

    # Run rules
    attack_edges = rules.evaluate_rules(nodes, edges)

    # Filter by severity if specified
    if args.severity:
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        min_level = severity_order.get(args.severity, 3)
        attack_edges = [
            e for e in attack_edges
            if severity_order.get(e.properties.get("severity", "medium"), 2) <= min_level
        ]

    # Write attack paths
    write_jsonl((e.to_dict() for e in attack_edges), input_dir / "attack_paths.jsonl")

    # Summary
    by_severity = {}
    for e in attack_edges:
        sev = e.properties.get("severity", "medium")
        by_severity[sev] = by_severity.get(sev, 0) + 1

    print(json.dumps({
        "total_findings": len(attack_edges),
        "by_severity": by_severity,
        "output": str(input_dir / "attack_paths.jsonl")
    }, indent=2))

    return 0


def cmd_export(args: argparse.Namespace) -> int:
    """Execute the export command."""
    from arguscloud.core.graph import GraphData, Node, Edge
    from arguscloud.exporters import JSONExporter, SARIFExporter, HTMLExporter

    input_dir = Path(args.input)

    print(f"Exporting findings from {input_dir}...")

    # Load data
    nodes_path = input_dir / "nodes.jsonl"
    attack_path = input_dir / "attack_paths.jsonl"

    if not nodes_path.exists():
        print("Normalized data not found. Run 'arguscloud normalize' first.")
        return 1

    nodes = []
    with nodes_path.open("r", encoding="utf-8") as f:
        for line in f:
            data = json.loads(line)
            nodes.append(Node(
                id=data["id"],
                type=data["type"],
                properties=data.get("properties", {})
            ))

    attack_paths = []
    if attack_path.exists():
        with attack_path.open("r", encoding="utf-8") as f:
            for line in f:
                data = json.loads(line)
                attack_paths.append(Edge(
                    src=data["src"],
                    dst=data["dst"],
                    type=data["type"],
                    properties=data.get("properties", {})
                ))

    graph = GraphData(nodes=nodes, edges=attack_paths)

    # Export
    if args.format == "json":
        exporter = JSONExporter(graph, attack_paths)
        ext = ".json"
    elif args.format == "sarif":
        exporter = SARIFExporter(graph, attack_paths)
        ext = ".sarif"
    elif args.format == "html":
        exporter = HTMLExporter(graph, attack_paths)
        ext = ".html"
    else:
        print(f"Unknown format: {args.format}")
        return 1

    output_path = args.output or str(input_dir / f"report{ext}")
    exporter.export_to_file(output_path)

    print(f"Exported to {output_path}")
    return 0


def cmd_serve(args: argparse.Namespace) -> int:
    """Execute the serve command."""
    from arguscloud.api import create_app
    from arguscloud.api.auth import AuthConfig

    auth_config = None
    if args.no_auth:
        auth_config = AuthConfig(enabled=False)

    app = create_app(
        args.neo4j_uri,
        args.neo4j_user,
        args.neo4j_password,
        auth_config
    )

    print(f"ArgusCloud API starting on http://{args.host}:{args.port}")
    app.run(host=args.host, port=args.port)
    return 0


def flatten_props(props: dict) -> dict:
    """Flatten nested objects to JSON strings for Neo4j compatibility."""
    flat = {}
    for k, v in props.items():
        if isinstance(v, (dict, list)):
            flat[k] = json.dumps(v)
        elif v is None:
            flat[k] = ""
        else:
            flat[k] = v
    return flat


def cmd_import(args: argparse.Namespace) -> int:
    """Execute the import command."""
    from neo4j import GraphDatabase

    input_dir = Path(args.input)

    print(f"Importing data from {input_dir} to Neo4j...")

    # Load data
    nodes_path = input_dir / "nodes.jsonl"
    edges_path = input_dir / "edges.jsonl"
    attack_path = input_dir / "attack_paths.jsonl"

    if not nodes_path.exists():
        print("Normalized data not found. Run 'arguscloud normalize' first.")
        return 1

    driver = GraphDatabase.driver(
        args.neo4j_uri,
        auth=(args.neo4j_user, args.neo4j_password)
    )

    node_count = 0
    edge_count = 0

    with driver.session() as session:
        if args.clear:
            print("Clearing existing data...")
            session.run("MATCH (n) DETACH DELETE n")

        # Import nodes
        print("Importing nodes...")
        with nodes_path.open("r", encoding="utf-8") as f:
            for line in f:
                data = json.loads(line)
                props = flatten_props(data.get("properties", {}))
                props["provider"] = data.get("provider", "aws")
                session.run(
                    "CREATE (n:Resource {id: $id, type: $type}) SET n += $props",
                    id=data["id"],
                    type=data["type"],
                    props=props
                )
                node_count += 1

        # Import edges
        print("Importing edges...")
        for path in [edges_path, attack_path]:
            if not path.exists():
                continue
            with path.open("r", encoding="utf-8") as f:
                for line in f:
                    data = json.loads(line)
                    props = flatten_props(data.get("properties", {}))
                    session.run(
                        """
                        MATCH (a:Resource {id: $src})
                        MATCH (b:Resource {id: $dst})
                        CREATE (a)-[r:REL {type: $type}]->(b)
                        SET r += $props
                        """,
                        src=data["src"],
                        dst=data["dst"],
                        type=data["type"],
                        props=props
                    )
                    edge_count += 1

    driver.close()
    print(f"Import complete! {node_count} nodes, {edge_count} edges")
    return 0


def cmd_keygen(args: argparse.Namespace) -> int:
    """Execute the keygen command."""
    from arguscloud.api.auth import generate_api_key

    api_key, hashed_key = generate_api_key(prefix=args.prefix)

    print("Generated API Key")
    print("=" * 60)
    print(f"API Key (give to user):  {api_key}")
    print(f"Hashed Key (store this): {hashed_key}")
    print()
    print("To use with environment variables:")
    print(f'  export ARGUSCLOUD_API_KEYS="mykey:{hashed_key}"')
    print()
    print("To use with curl:")
    print(f'  curl -H "X-API-Key: {api_key}" http://localhost:5000/graph')

    return 0


def main(args: Optional[List[str]] = None) -> int:
    """Main entry point for ArgusCloud CLI."""
    parsed = parse_args(args)

    if not parsed.command:
        print("Usage: arguscloud <command> [options]")
        print("Run 'arguscloud --help' for available commands")
        return 1

    commands = {
        "collect": cmd_collect,
        "normalize": cmd_normalize,
        "analyze": cmd_analyze,
        "export": cmd_export,
        "serve": cmd_serve,
        "import": cmd_import,
        "keygen": cmd_keygen,
    }

    handler = commands.get(parsed.command)
    if handler:
        return handler(parsed)

    print(f"Unknown command: {parsed.command}")
    return 1


if __name__ == "__main__":
    sys.exit(main())
