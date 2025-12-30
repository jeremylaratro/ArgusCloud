# CloudHound Remaining Remediation Plan

**Date:** 2025-12-30
**Status:** Phase 1-2 Security Fixes Complete
**Remaining:** Documentation, Architecture, Testing, Operations

---

## Executive Summary

All critical security vulnerabilities have been addressed. This plan covers the remaining 25 items across 5 categories, organized into 4 implementation phases.

---

## Phase 1: Documentation (Priority: HIGH)

### 1.1 API Documentation with OpenAPI/Swagger

**Effort:** Medium
**Files to create/modify:**
- `cloudhound/api/openapi.py` (new)
- `cloudhound/api/server.py` (modify)
- `docs/api-reference.md` (new)

**Implementation:**

```python
# cloudhound/api/openapi.py
from flask_openapi3 import OpenAPI, Info, Tag
from pydantic import BaseModel, Field
from typing import List, Dict, Any, Optional

info = Info(title="CloudHound API", version="0.2.0")

# Define tags for grouping
graph_tag = Tag(name="Graph", description="Graph data operations")
auth_tag = Tag(name="Authentication", description="Auth endpoints")
collect_tag = Tag(name="Collection", description="Cloud data collection")
export_tag = Tag(name="Export", description="Data export operations")

# Request/Response models (extend existing models.py)
class GraphQuery(BaseModel):
    provider: Optional[str] = Field(None, description="Filter by cloud provider")
    type: Optional[str] = Field(None, description="Filter by node type")
    limit: int = Field(500, ge=1, le=10000, description="Max results")

class GraphResponse(BaseModel):
    nodes: List[Dict[str, Any]]
    edges: List[Dict[str, Any]]
    meta: Dict[str, Any]
```

**Steps:**
1. Add `flask-openapi3>=3.0.0` to dependencies
2. Create openapi.py with all endpoint schemas
3. Modify server.py to use OpenAPI app factory
4. Auto-generate docs at `/docs` endpoint
5. Export OpenAPI spec to `docs/openapi.yaml`

**Acceptance Criteria:**
- [ ] Interactive Swagger UI at `/docs`
- [ ] All endpoints documented with request/response schemas
- [ ] Authentication documented
- [ ] Error responses documented

---

### 1.2 Security Documentation

**Effort:** Medium
**Files to create:**
- `docs/security.md`
- `docs/deployment-security.md`
- `SECURITY.md` (root level)

**Content outline for `docs/security.md`:**

```markdown
# CloudHound Security Guide

## Credential Handling
- Never store credentials in code or config files
- Use environment variables or AWS credential providers
- Credentials cleared from memory after use

## IAM Policy Requirements
- Minimum required permissions for collection
- Read-only policy template
- Cross-account role configuration

## Network Security
- Run API behind reverse proxy
- TLS configuration
- Firewall recommendations

## Neo4j Security
- Authentication configuration
- Network isolation
- Encryption at rest

## Data Retention
- Graph data lifecycle
- Audit logging
- PII considerations

## Incident Response
- Security issue reporting
- Vulnerability disclosure process
```

**Content for `SECURITY.md`:**
```markdown
# Security Policy

## Reporting a Vulnerability

Please report security vulnerabilities to: security@example.com

Do NOT open public issues for security vulnerabilities.

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.2.x   | Yes       |
| < 0.2   | No        |
```

---

### 1.3 Contributing Guide

**Effort:** Low
**File:** `CONTRIBUTING.md`

**Content:**

```markdown
# Contributing to CloudHound

## Development Setup

1. Clone the repository
2. Create virtual environment: `python -m venv venv`
3. Install dev dependencies: `pip install -e ".[dev]"`
4. Start Neo4j: `docker-compose up -d neo4j`
5. Run tests: `pytest`

## Code Style

- Use `ruff` for linting: `ruff check cloudhound/`
- Use `black` for formatting: `black cloudhound/`
- Type hints required for public functions
- Docstrings required for modules and classes

## Testing Requirements

- All new code must have tests
- Maintain >80% coverage
- Run full suite before PR: `pytest --cov`

## Pull Request Process

1. Create feature branch from `main`
2. Make changes with tests
3. Update documentation if needed
4. Run linting and tests
5. Submit PR with description

## Commit Messages

Use conventional commits:
- `feat:` New features
- `fix:` Bug fixes
- `docs:` Documentation
- `refactor:` Code changes
- `test:` Test changes
```

---

### 1.4 Deployment Guide

**Effort:** Medium
**Files to create:**
- `docs/deployment.md`
- `docker-compose.prod.yml`
- `deploy/kubernetes/` directory

**Content for `docs/deployment.md`:**

```markdown
# CloudHound Deployment Guide

## Docker Deployment

### Quick Start
docker-compose -f docker-compose.prod.yml up -d

### Environment Variables
| Variable | Description | Default |
|----------|-------------|---------|
| CLOUDHOUND_API_PORT | API port | 9847 |
| CLOUDHOUND_NEO4J_URI | Neo4j connection | bolt://localhost:7687 |
| CLOUDHOUND_NEO4J_PASSWORD | Neo4j password | (required) |
| CLOUDHOUND_JWT_SECRET | JWT signing key | (auto-generated) |
| CLOUDHOUND_CORS_ORIGINS | Allowed origins | http://localhost:8080 |

## Kubernetes Deployment

See `deploy/kubernetes/` for manifests.

## Reverse Proxy (Nginx)

server {
    listen 443 ssl;
    server_name cloudhound.example.com;

    location / {
        proxy_pass http://localhost:9847;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }
}

## SSL/TLS Configuration

Use Let's Encrypt or your certificate provider.
```

---

## Phase 2: Code Quality & Architecture (Priority: MEDIUM-HIGH)

### 2.1 Database Abstraction Layer

**Effort:** High
**Files to create:**
- `cloudhound/repositories/__init__.py`
- `cloudhound/repositories/base.py`
- `cloudhound/repositories/neo4j_repository.py`

**Implementation:**

```python
# cloudhound/repositories/base.py
from abc import ABC, abstractmethod
from typing import List, Optional, Dict, Any
from dataclasses import dataclass

@dataclass
class NodeFilter:
    provider: Optional[str] = None
    node_type: Optional[str] = None
    limit: int = 500

@dataclass
class Node:
    id: str
    type: str
    provider: str
    properties: Dict[str, Any]

@dataclass
class Edge:
    src: str
    dst: str
    type: str
    properties: Dict[str, Any]

class GraphRepository(ABC):
    @abstractmethod
    def get_nodes(self, filters: NodeFilter) -> List[Node]:
        """Get nodes with optional filtering."""
        pass

    @abstractmethod
    def get_edges(self, filters: NodeFilter) -> List[Edge]:
        """Get edges with optional filtering."""
        pass

    @abstractmethod
    def get_attack_paths(self, severity: Optional[str] = None) -> List[Edge]:
        """Get attack path edges."""
        pass

    @abstractmethod
    def execute_query(self, cypher: str, params: Dict = None) -> List[Dict]:
        """Execute validated Cypher query."""
        pass

    @abstractmethod
    def health_check(self) -> bool:
        """Check database connectivity."""
        pass
```

```python
# cloudhound/repositories/neo4j_repository.py
from neo4j import Driver
from .base import GraphRepository, Node, Edge, NodeFilter

class Neo4jGraphRepository(GraphRepository):
    def __init__(self, driver: Driver):
        self.driver = driver

    def get_nodes(self, filters: NodeFilter) -> List[Node]:
        query = "MATCH (n) "
        params = {}

        conditions = []
        if filters.provider:
            conditions.append("n.provider = $provider")
            params["provider"] = filters.provider
        if filters.node_type:
            conditions.append("n.type = $type")
            params["type"] = filters.node_type

        if conditions:
            query += "WHERE " + " AND ".join(conditions) + " "

        query += f"RETURN n LIMIT {filters.limit}"

        with self.driver.session() as session:
            result = session.run(query, params)
            return [self._record_to_node(r) for r in result]

    def _record_to_node(self, record) -> Node:
        n = record["n"]
        return Node(
            id=n.get("id"),
            type=n.get("type"),
            provider=n.get("provider", "unknown"),
            properties=dict(n)
        )

    # ... implement other methods
```

**Migration Steps:**
1. Create repository interfaces
2. Implement Neo4j repository
3. Update server.py to use repository
4. Add repository to dependency injection
5. Update tests to mock repository

---

### 2.2 Add Type Hints to API Routes

**Effort:** Low
**File:** `cloudhound/api/server.py`

**Example changes:**

```python
from flask import Response
from typing import Tuple, Union

ResponseType = Union[Response, Tuple[Response, int], Tuple[dict, int]]

@app.route("/health")
def health() -> ResponseType:
    """Health check endpoint."""
    ...

@app.route("/graph")
@require_auth
def get_graph() -> ResponseType:
    """Get graph data with optional filters."""
    ...
```

**Steps:**
1. Add return type hints to all route handlers
2. Run `mypy cloudhound/api/` to verify
3. Add mypy to CI checks

---

### 2.3 Extract Common Collector Patterns

**Effort:** Medium
**Files to modify:**
- `cloudhound/collectors/aws/base.py` (new)
- All collector files

**Implementation:**

```python
# cloudhound/collectors/aws/base.py
from typing import List, Dict, Any, Callable
from botocore.exceptions import ClientError
import logging

logger = logging.getLogger(__name__)

def paginated_collect(
    client,
    method: str,
    result_key: str,
    **kwargs
) -> List[Dict[str, Any]]:
    """Generic paginated AWS API collection."""
    results = []
    try:
        paginator = client.get_paginator(method)
        for page in paginator.paginate(**kwargs):
            results.extend(page.get(result_key, []))
    except ClientError as e:
        logger.warning(f"AWS API error in {method}: {e.response['Error']['Code']}")
    except Exception as e:
        logger.warning(f"Collection error in {method}: {type(e).__name__}")
    return results

def safe_collect(
    func: Callable,
    service_name: str
) -> Callable:
    """Decorator for safe collection with standard error handling."""
    def wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except ClientError as e:
            logger.warning(f"{service_name} collection failed: {e.response['Error']['Code']}")
            return []
        except Exception as e:
            logger.warning(f"{service_name} collection error: {type(e).__name__}")
            return []
    return wrapper
```

---

### 2.4 Legacy Code Deprecation

**Effort:** Low
**Files to modify:**
- `awshound/__init__.py`
- `pyproject.toml`

**Steps:**
1. Add deprecation warning to awshound entry point
2. Update pyproject.toml with deprecation notice
3. Document migration path
4. Plan removal for version 0.3.0

```python
# awshound/__init__.py
import warnings

warnings.warn(
    "awshound is deprecated and will be removed in v0.3.0. "
    "Use 'cloudhound' instead.",
    DeprecationWarning,
    stacklevel=2
)
```

---

## Phase 3: Testing Improvements (Priority: HIGH)

### 3.1 API Integration Tests

**Effort:** Medium
**Files to create:**
- `tests/integration/__init__.py`
- `tests/integration/test_api_integration.py`
- `tests/integration/conftest.py`

**Implementation:**

```python
# tests/integration/conftest.py
import pytest
from testcontainers.neo4j import Neo4jContainer

@pytest.fixture(scope="session")
def neo4j_container():
    """Start Neo4j container for integration tests."""
    with Neo4jContainer("neo4j:5") as neo4j:
        yield neo4j

@pytest.fixture
def app_with_db(neo4j_container):
    """Create app with real database."""
    from cloudhound.api.server import create_app

    app = create_app(
        neo4j_uri=neo4j_container.get_connection_url(),
        neo4j_user="neo4j",
        neo4j_password="test"
    )
    app.config["TESTING"] = True
    return app
```

```python
# tests/integration/test_api_integration.py
class TestAPIIntegration:
    def test_full_workflow(self, app_with_db):
        """Test complete workflow: upload -> query -> export."""
        client = app_with_db.test_client()

        # Create profile with data
        response = client.post("/profiles", json={
            "name": "test-profile",
            "nodes": [{"id": "node1", "type": "Role", "provider": "aws"}],
            "edges": []
        })
        assert response.status_code == 201

        # Query the data
        response = client.get("/graph?provider=aws")
        assert response.status_code == 200
        assert len(response.json["nodes"]) == 1

        # Export
        response = client.get("/export/json")
        assert response.status_code == 200
```

---

### 3.2 Collector Tests with Moto

**Effort:** Medium
**Files to create:**
- `tests/collectors/__init__.py`
- `tests/collectors/test_iam_collector.py`
- `tests/collectors/test_s3_collector.py`

**Implementation:**

```python
# tests/collectors/test_iam_collector.py
import pytest
from moto import mock_aws
import boto3
from cloudhound.collectors.aws.iam import collect_iam_data

@mock_aws
def test_iam_roles_collected():
    """Test IAM role collection."""
    # Setup mock IAM
    iam = boto3.client("iam", region_name="us-east-1")
    iam.create_role(
        RoleName="TestRole",
        AssumeRolePolicyDocument='{"Version": "2012-10-17", "Statement": []}'
    )

    # Create session
    session = boto3.Session(region_name="us-east-1")

    # Collect
    nodes, edges = collect_iam_data(session)

    # Assert
    role_nodes = [n for n in nodes if n["type"] == "Role"]
    assert len(role_nodes) == 1
    assert role_nodes[0]["properties"]["name"] == "TestRole"

@mock_aws
def test_iam_policies_collected():
    """Test IAM policy collection."""
    iam = boto3.client("iam", region_name="us-east-1")
    iam.create_policy(
        PolicyName="TestPolicy",
        PolicyDocument='{"Version": "2012-10-17", "Statement": []}'
    )

    session = boto3.Session(region_name="us-east-1")
    nodes, edges = collect_iam_data(session)

    policy_nodes = [n for n in nodes if n["type"] == "Policy"]
    assert len(policy_nodes) >= 1
```

---

### 3.3 Security Tests

**Effort:** Medium
**File:** `tests/security/test_api_security.py`

```python
# tests/security/test_api_security.py
import pytest

class TestCypherInjection:
    """Test Cypher injection prevention."""

    @pytest.mark.parametrize("payload", [
        "MATCH (n) DELETE n RETURN n",
        "MATCH (n) SET n.pwned=true RETURN n",
        "MATCH (n) DETACH DELETE n",
        "CALL db.labels() YIELD label RETURN label",  # This should be allowed
        "MATCH (n)/**/DELETE/**/n RETURN n",
        "MATCH (n) RE" + "MOVE n.prop RETURN n",
    ])
    def test_injection_blocked(self, client, payload):
        """Verify injection attempts are blocked."""
        response = client.post("/query", json={"cypher": payload})
        # DELETE/SET/REMOVE should be blocked
        if any(kw in payload.upper() for kw in ["DELETE", "SET", "REMOVE"]):
            assert response.status_code == 403

class TestAuthBypass:
    """Test authentication bypass attempts."""

    def test_missing_auth_header(self, client_with_auth):
        response = client_with_auth.get("/graph")
        assert response.status_code == 401

    def test_invalid_token(self, client_with_auth):
        response = client_with_auth.get(
            "/graph",
            headers={"Authorization": "Bearer invalid.token.here"}
        )
        assert response.status_code == 401

    def test_expired_token(self, client_with_auth, expired_token):
        response = client_with_auth.get(
            "/graph",
            headers={"Authorization": f"Bearer {expired_token}"}
        )
        assert response.status_code == 401

class TestRateLimiting:
    """Test rate limiting (when implemented)."""

    @pytest.mark.skip(reason="Rate limiting not yet implemented")
    def test_rate_limit_enforced(self, client):
        for i in range(150):
            response = client.get("/health")
        assert response.status_code == 429
```

---

## Phase 4: Operations & Frontend (Priority: MEDIUM)

### 4.1 Metrics and Observability

**Effort:** Medium
**Files to create/modify:**
- `cloudhound/api/metrics.py` (new)
- `cloudhound/api/server.py` (modify)

**Implementation:**

```python
# cloudhound/api/metrics.py
from prometheus_client import Counter, Histogram, generate_latest
from functools import wraps
import time

# Metrics
REQUEST_COUNT = Counter(
    'cloudhound_requests_total',
    'Total requests',
    ['method', 'endpoint', 'status']
)

REQUEST_LATENCY = Histogram(
    'cloudhound_request_latency_seconds',
    'Request latency',
    ['method', 'endpoint']
)

COLLECTION_DURATION = Histogram(
    'cloudhound_collection_duration_seconds',
    'Collection duration by service',
    ['provider', 'service']
)

def track_request(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        start = time.time()
        response = func(*args, **kwargs)
        duration = time.time() - start

        REQUEST_COUNT.labels(
            method=request.method,
            endpoint=request.endpoint,
            status=response.status_code
        ).inc()

        REQUEST_LATENCY.labels(
            method=request.method,
            endpoint=request.endpoint
        ).observe(duration)

        return response
    return wrapper

# Add /metrics endpoint
@app.route("/metrics")
def metrics():
    return generate_latest(), 200, {'Content-Type': 'text/plain'}
```

---

### 4.2 Rate Limiting

**Effort:** Low
**File:** `cloudhound/api/server.py`

```python
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

limiter = Limiter(
    key_func=get_remote_address,
    default_limits=["1000 per hour"]
)

def create_app(...):
    app = Flask(__name__)
    limiter.init_app(app)

    @app.route("/query")
    @limiter.limit("100 per minute")
    def query():
        ...

    @app.route("/collect/aws")
    @limiter.limit("10 per hour")
    def collect_aws():
        ...
```

---

### 4.3 Graceful Shutdown

**Effort:** Low
**File:** `cloudhound/api/server.py`

```python
import signal
import sys
from threading import Event

shutdown_event = Event()

def graceful_shutdown(signum, frame):
    """Handle shutdown signals."""
    logger.info("Shutdown signal received, finishing requests...")
    shutdown_event.set()

    # Give requests 30 seconds to complete
    time.sleep(30)

    # Close Neo4j connection
    if driver:
        driver.close()

    logger.info("Shutdown complete")
    sys.exit(0)

signal.signal(signal.SIGTERM, graceful_shutdown)
signal.signal(signal.SIGINT, graceful_shutdown)
```

---

### 4.4 UI Refactoring Plan

**Effort:** High
**Current:** Single 8,534 line `index.html`
**Target:** Component-based architecture

**Proposed Structure:**
```
ui/
├── index.html           # Shell HTML only
├── css/
│   ├── main.css
│   ├── graph.css
│   └── components.css
├── js/
│   ├── app.js           # Main application
│   ├── api.js           # API client
│   ├── state.js         # State management
│   ├── graph.js         # Cytoscape graph
│   ├── sidebar.js       # Sidebar components
│   └── utils.js         # Utilities
└── build/
    └── bundle.js        # Production bundle
```

**Migration Steps:**
1. Extract CSS to separate files
2. Extract JavaScript modules
3. Create simple state management
4. Add build process (esbuild/vite)
5. Add minification for production

**Build Configuration (esbuild):**
```javascript
// build.js
const esbuild = require('esbuild');

esbuild.build({
    entryPoints: ['js/app.js'],
    bundle: true,
    minify: true,
    outfile: 'build/bundle.js',
}).catch(() => process.exit(1));
```

---

## Implementation Schedule

| Phase | Items | Estimated Effort |
|-------|-------|------------------|
| **Phase 1: Documentation** | 1.1-1.4 | 3-4 days |
| **Phase 2: Architecture** | 2.1-2.4 | 5-7 days |
| **Phase 3: Testing** | 3.1-3.3 | 4-5 days |
| **Phase 4: Operations** | 4.1-4.4 | 5-7 days |

**Total Estimated Effort:** 17-23 days

---

## Dependencies to Add

```toml
# pyproject.toml additions
dependencies = [
    # ... existing
    "flask-openapi3>=3.0.0",    # API documentation
    "flask-limiter>=3.0.0",     # Rate limiting
    "prometheus-client>=0.17.0", # Metrics
]

[project.optional-dependencies]
dev = [
    # ... existing
    "testcontainers>=3.0.0",    # Integration tests
    "moto>=4.0.0",              # AWS mocking
]
```

---

## Priority Recommendations

### Immediate (This Week)
1. **1.3 CONTRIBUTING.md** - Low effort, high value
2. **2.4 Legacy deprecation** - Low effort, prevents confusion
3. **1.2 SECURITY.md** - Required for responsible disclosure

### Short-term (Next 2 Weeks)
1. **1.1 API Documentation** - Critical for users
2. **3.1 Integration tests** - Confidence in changes
3. **4.2 Rate limiting** - Security hardening

### Medium-term (Month 1)
1. **2.1 Database abstraction** - Architectural improvement
2. **3.2 Collector tests** - Coverage improvement
3. **4.1 Metrics** - Operational visibility

### Long-term (Month 2+)
1. **4.4 UI refactoring** - Large effort, not blocking
2. **GCP/Azure collectors** - Feature expansion

---

## Success Metrics

| Metric | Current | Target |
|--------|---------|--------|
| Test Coverage | ~60% | >80% |
| API Docs | None | 100% endpoints |
| Security Docs | None | Complete |
| Type Coverage | ~40% | >80% |
| Build Time | N/A | <10s |

---

**End of Plan**
