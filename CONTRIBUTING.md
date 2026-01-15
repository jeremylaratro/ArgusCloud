# Contributing to ArgusCloud

Thank you for your interest in contributing to ArgusCloud! This document provides guidelines and instructions for contributing.

## Table of Contents

- [Development Setup](#development-setup)
- [Code Style](#code-style)
- [Testing Requirements](#testing-requirements)
- [Pull Request Process](#pull-request-process)
- [Commit Messages](#commit-messages)
- [Reporting Issues](#reporting-issues)

## Development Setup

### Prerequisites

- Python 3.10 or higher
- Neo4j 5.x (for integration testing)
- Docker (optional, for containerized Neo4j)

### Installation

1. **Clone the repository:**
   ```bash
   git clone https://github.com/jeremylaratro/arguscloud.git
   cd arguscloud
   ```

2. **Create a virtual environment:**
   ```bash
   python -m venv venv
   source venv/bin/activate  # Linux/macOS
   # or
   .\venv\Scripts\activate   # Windows
   ```

3. **Install development dependencies:**
   ```bash
   pip install -e ".[dev]"
   ```

4. **Start Neo4j (using Docker):**
   ```bash
   docker-compose up -d neo4j
   ```

   Or use your local Neo4j installation with:
   - URI: `bolt://localhost:7687`
   - Default credentials: `neo4j` / `password`

5. **Run tests to verify setup:**
   ```bash
   pytest
   ```

### Environment Variables

Create a `.env` file for local development:

```bash
ARGUSCLOUD_NEO4J_URI=bolt://localhost:7687
ARGUSCLOUD_NEO4J_USER=neo4j
ARGUSCLOUD_NEO4J_PASSWORD=password
ARGUSCLOUD_AUTH_ENABLED=false
ARGUSCLOUD_LOG_LEVEL=DEBUG
```

## Code Style

### Python Style Guide

We use the following tools to maintain code quality:

- **Ruff** for linting: `ruff check arguscloud/`
- **Black** for formatting: `black arguscloud/`
- **isort** for import sorting: `isort arguscloud/`

Run all checks before committing:
```bash
ruff check arguscloud/ tests/
black --check arguscloud/ tests/
```

### Type Hints

- Type hints are **required** for all public functions and methods
- Use `typing` module for complex types
- Run `mypy arguscloud/` to check type correctness

```python
# Good
def get_nodes(self, filters: NodeFilter) -> List[Dict[str, Any]]:
    ...

# Bad
def get_nodes(self, filters):
    ...
```

### Docstrings

- Use Google-style docstrings for modules, classes, and public functions
- Include parameter descriptions and return types

```python
def collect_iam_roles(session: boto3.Session) -> Tuple[str, List[Dict]]:
    """Collect IAM roles from AWS account.

    Args:
        session: Authenticated boto3 session.

    Returns:
        Tuple of (service_name, list of role records).

    Raises:
        ClientError: If AWS API call fails.
    """
```

### Code Organization

- Keep functions focused and under 50 lines when possible
- Use meaningful variable names
- Avoid magic numbers - use constants from `arguscloud/constants.py`
- Handle errors explicitly - no bare `except:` clauses

## Testing Requirements

### Running Tests

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=arguscloud --cov-report=html

# Run specific test file
pytest tests/test_api_server.py

# Run tests matching pattern
pytest -k "test_health"
```

### Test Requirements

1. **All new code must have tests**
   - Unit tests for functions and methods
   - Integration tests for API endpoints

2. **Maintain >80% code coverage**
   - Check coverage: `pytest --cov=arguscloud`

3. **Test naming convention:**
   ```python
   def test_<function_name>_<scenario>():
       ...

   # Examples:
   def test_health_endpoint_success():
   def test_health_endpoint_db_failure():
   def test_validate_cypher_blocks_delete():
   ```

4. **Use fixtures for common setup:**
   ```python
   @pytest.fixture
   def mock_driver():
       ...

   def test_something(mock_driver):
       ...
   ```

### Test Organization

```
tests/
├── conftest.py           # Shared fixtures
├── test_api_server.py    # API endpoint tests
├── test_auth.py          # Authentication tests
├── test_models.py        # Pydantic model tests
├── test_rules_*.py       # Security rule tests
└── integration/          # Integration tests (require Neo4j)
```

## Pull Request Process

### Before Submitting

1. **Create a feature branch:**
   ```bash
   git checkout -b feature/my-feature
   # or
   git checkout -b fix/bug-description
   ```

2. **Make your changes with tests**

3. **Run the full test suite:**
   ```bash
   pytest
   ```

4. **Run linting:**
   ```bash
   ruff check arguscloud/ tests/
   black --check arguscloud/ tests/
   ```

5. **Update documentation if needed**

### PR Guidelines

- **Title:** Clear, concise description of the change
- **Description:** Include:
  - What the PR does
  - Why it's needed
  - How to test it
  - Any breaking changes

- **Size:** Keep PRs focused and reasonably sized
  - Large changes should be split into smaller PRs
  - Refactoring should be separate from new features

### Review Process

1. All PRs require at least one approval
2. CI checks must pass (tests, linting)
3. Address reviewer feedback
4. Squash commits before merging (if requested)

## Commit Messages

We use [Conventional Commits](https://www.conventionalcommits.org/):

```
<type>(<scope>): <description>

[optional body]

[optional footer]
```

### Types

- `feat:` New feature
- `fix:` Bug fix
- `docs:` Documentation only
- `style:` Formatting, no code change
- `refactor:` Code change that neither fixes nor adds
- `perf:` Performance improvement
- `test:` Adding or updating tests
- `chore:` Maintenance tasks

### Examples

```
feat(api): add rate limiting to query endpoint

fix(auth): handle expired JWT tokens correctly

docs: update deployment guide with Docker instructions

refactor(collectors): extract common pagination logic

test(api): add integration tests for profile endpoints
```

## Reporting Issues

### Bug Reports

Include:
- ArgusCloud version
- Python version
- Operating system
- Steps to reproduce
- Expected vs actual behavior
- Error messages/logs

### Feature Requests

Include:
- Use case description
- Proposed solution (if any)
- Alternatives considered

### Security Issues

**DO NOT** open public issues for security vulnerabilities.
See [SECURITY.md](SECURITY.md) for reporting instructions.

## Questions?

- Open a [Discussion](https://github.com/jeremylaratro/arguscloud/discussions) for questions
- Check existing issues before creating new ones
- Join our community chat (if available)

---

Thank you for contributing to ArgusCloud!
