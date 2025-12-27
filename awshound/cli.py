from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import List

from . import auth
from .bundle import write_jsonl, write_manifest
from .collector import collect_services
from .manifest import Manifest
from .modes import RunMode


DEFAULT_SERVICES = [
    "sts",
    "org",
    "iam",
    "iam-roles",
    "iam-users",
    "iam-policies",
    "cloudtrail",
    "guardduty",
    "s3",
    "kms",
    "vpc",
    "ec2",
    "ec2-images",
    "eks",
    "ecr",
    "lambda",
    "cloudformation",
    "codebuild",
    "secretsmanager",
    "ssm-parameters",
    "sns",
    "sqs",
    "securityhub",
    "detective",
    "config",
    "sso",
    "rds",
    "codepipeline",
    "cloudwatch",
    "waf",
    "shield",
    "fms",
]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="AWSHound collector CLI")
    parser.add_argument("command", choices=["collect", "normalize"], help="command to run")
    parser.add_argument("--output", "-o", default="awshound-output", help="directory for output bundle")
    parser.add_argument("--profile", help="AWS profile name")
    parser.add_argument("--region", help="AWS region override")
    parser.add_argument("--mode", choices=RunMode.values(), default=RunMode.FAST.value, help="collection mode")
    parser.add_argument(
        "--services",
        nargs="+",
        default=DEFAULT_SERVICES,
        help="services to collect (default: %(default)s)",
    )
    return parser.parse_args()


def run_collect(args: argparse.Namespace) -> None:
    session, caller = auth.resolve_session(profile=args.profile, region=args.region)
    manifest = Manifest.new(
        mode=RunMode(args.mode),
        caller_arn=caller.arn,
        account_id=caller.account,
        partition=caller.partition,
        region=caller.resolved_region,
        profile=args.profile or "default",
    )

    outputs = collect_services(session, services=args.services, manifest=manifest, mode=RunMode(args.mode))
    output_dir = Path(args.output)

    # Write raw outputs per service for transparency
    for svc, records in outputs.items():
        write_jsonl(records, output_dir / f"{svc}.jsonl")

    manifest_path = write_manifest(manifest, output_dir)
    print(json.dumps({"manifest": str(manifest_path), "services": list(outputs.keys())}, indent=2))


def run_normalize(args: argparse.Namespace) -> None:
    from . import normalize, rules

    output_dir = Path(args.output)
    raw: dict = {}
    for svc in args.services:
        path = output_dir / f"{svc}.jsonl"
        if not path.exists():
            continue
        with path.open("r", encoding="utf-8") as f:
            raw[svc] = [json.loads(line) for line in f]
    nodes, edges = normalize.normalize(raw)
    attack_edges = rules.evaluate_rules(nodes, edges)
    edges.extend(attack_edges)
    write_jsonl((n.to_dict() for n in nodes), output_dir / "nodes.jsonl")
    write_jsonl((e.to_dict() for e in edges), output_dir / "edges.jsonl")
    print(json.dumps({"normalized_nodes": len(nodes), "normalized_edges": len(edges)}, indent=2))


def main() -> None:
    args = parse_args()
    if args.command == "collect":
        run_collect(args)
    elif args.command == "normalize":
        run_normalize(args)
    else:  # pragma: no cover - defensive, should not hit due to argparse choices
        raise SystemExit(f"Unknown command {args.command}")


if __name__ == "__main__":
    main()
