# CloudHound

BloodHound-style graph analytics for AWS environments. Collect, normalize, and visualize AWS resources, trust relationships, and attack paths.

![Graph View](demo/screenshot-graph.png)

## Features

- **AWS Data Collection**: Enumerate IAM, S3, EC2, Lambda, EKS, RDS, and 30+ other AWS services
- **Graph Visualization**: Interactive graph showing trust relationships, permissions, and attack paths
- **Attack Path Analysis**: Automated detection of privilege escalation and lateral movement opportunities
- **Neo4j Integration**: Store and query data using Cypher
- **Offline Support**: Export bundles for air-gapped analysis

## Screenshots

### Graph View
Visualize organizational structure, trust relationships, and attack paths with severity-colored edges.

![Graph View](demo/screenshot-graph.png)

### Environment Summary
View object counts and details by type (Accounts, Roles, Users, S3 Buckets, etc.).

![Environment View](demo/screenshot-environment.png)

### Data Management
Import/export data, fetch from API, or load files directly for offline analysis.

![Data Management](demo/screenshot-data.png)

## Installation

```bash
# Clone the repository
git clone https://github.com/jeremylaratro/cloudhound.git
cd cloudhound

# Install Python dependencies
pip install -r requirements.txt

# (Optional) Start Neo4j
docker run -d --name neo4j \
  -p 7474:7474 -p 7687:7687 \
  -e NEO4J_AUTH=neo4j/letmein123 \
  neo4j:latest
```

## Usage

### Collect AWS Data

```bash
# Using default AWS profile
python -m awshound.cli collect --output ./output

# Using specific profile and region
python -m awshound.cli collect --profile myprofile --region us-east-1 --output ./output

# Collect specific services only
python -m awshound.cli collect --services iam s3 ec2 lambda
```

### Normalize Data

```bash
# Generate nodes and edges from collected data
python -m awshound.cli normalize --output ./output
```

### Load into Neo4j

```bash
python scripts/load_to_neo4j.py \
  --nodes output/nodes.jsonl \
  --edges output/edges.jsonl \
  --uri bolt://localhost:7687 \
  --user neo4j \
  --password letmein123
```

### Start the UI

```bash
# Start the API server
PYTHONPATH=. python server/api.py --uri bolt://localhost:7687 --user neo4j --password letmein123 --port 5000

# Start the UI (in another terminal)
cd ui && python -m http.server 8001
```

Open http://localhost:8001 in your browser.

## Supported Services

| Category | Services |
|----------|----------|
| Identity | IAM (users, roles, policies), STS, SSO |
| Compute | EC2, Lambda, EKS, ECR |
| Storage | S3, RDS |
| Security | CloudTrail, GuardDuty, SecurityHub, Detective, WAF, Shield |
| Networking | VPC |
| Management | Organizations, CloudFormation, Config |
| Messaging | SNS, SQS |
| Secrets | Secrets Manager, SSM Parameters, KMS |
| CI/CD | CodeBuild, CodePipeline |
| Monitoring | CloudWatch |

## Attack Path Rules

CloudHound automatically detects potential attack paths including:

- **Privilege Escalation**: Users/roles that can escalate to admin
- **Cross-Account Access**: Trust relationships allowing lateral movement
- **Public Exposure**: S3 buckets, security groups with public access
- **Credential Access**: Roles with access to secrets or KMS keys

## Architecture

```
awshound/
├── auth.py        # AWS authentication handling
├── collector.py   # Service data collection
├── normalize.py   # Convert raw data to graph nodes/edges
├── rules.py       # Attack path detection rules
├── graph.py       # Graph operations
└── cli.py         # Command-line interface

server/
└── api.py         # REST API for UI

ui/
└── index.html     # Web-based graph viewer
```

## Requirements

- Python 3.10+
- AWS credentials with read permissions
- Neo4j 4.x+ (optional, for persistence)

## License

This software is licensed for **non-commercial use only**. See [LICENSE](LICENSE) for details.

For commercial licensing inquiries, please contact the author.
