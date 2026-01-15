# ArgusCloud Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.5.0] - 2026-01-14

### Changed
- **Project Rename**: CloudHound → ArgusCloud
  - Renamed Python package from `cloudhound` to `arguscloud`
  - Updated CLI command from `cloudhound` to `arguscloud`
  - Updated all environment variables from `CLOUDHOUND_*` to `ARGUSCLOUD_*`
  - Updated Docker container names from `cloudhound-*` to `arguscloud-*`
  - Updated all documentation, UI branding, and references
  - Updated test suite imports and fixtures

## [0.4.1] - 2026-01-14

### Added
- **Startup Script**: Comprehensive start.sh script for streamlined deployment
  - ASCII banner with ArgusCloud branding
  - Dependency checking (Docker, Docker Compose)
  - Environment configuration with dev defaults and prod validation
  - Service startup with progress indicators
  - Access URL display with health checks
  - Next steps guidance and documentation links
  - Helper commands (--status, --logs, --stop, --clean)
  - Support for both development and production modes

## [0.4.0] - 2026-01-13

### Added
- **Docker Deployment**: Complete containerization infrastructure
  - Backend API Dockerfile with multi-stage build
  - Frontend UI Dockerfile with Nginx
  - Development docker-compose.yml configuration
  - Production docker-compose.prod.yml with health checks
  - Environment configuration template (.env.example)
  - WSGI production server configuration
- **Test Suite Expansion**: 187 new tests across 6 test modules
  - tests/conftest.py - Shared pytest fixtures and utilities
  - tests/test_repositories.py - 24 repository layer tests
  - tests/test_api_collect.py - 24 collection endpoint tests
  - tests/test_collectors_session.py - 32 session management tests
  - tests/test_api_errors.py - 30 error handling tests
  - tests/test_config.py - 34 configuration tests
  - tests/test_plugins.py - 43 plugin system tests
- **Documentation Archive**: Historical analysis documents moved to docs/archive/

### Changed
- **UI Documentation**: Comprehensive rewrite of ui/README.md with architecture details
- **Security Policy**: Updated SECURITY.md with version 0.4.0 in supported versions table
- **Contributing Guide**: Fixed repository URL in CONTRIBUTING.md
- **Legacy Naming**: Updated remaining AWSHound references to ArgusCloud in docs/

### Removed
- **Historical Documents**: Archived CRITICAL_ANALYSIS.md and REMAINING_REMEDIATION_PLAN.md to docs/archive/

### Fixed
- **Documentation Consistency**: Standardized naming and references across all documentation
- **Production Deployment**: Enhanced docker-compose.prod.yml with proper networking and volumes

## [0.3.0] - 2025-12-30

### Added
- **Testing Infrastructure**: Comprehensive integration test suite with Neo4j test containers
- **Security Testing**: API security test suite covering authentication, authorization, and input validation
- **AWS Collector Tests**: IAM collector tests using moto for AWS service mocking
- **Prometheus Metrics**: Production-grade metrics endpoint for monitoring API performance and health
- **Rate Limiting**: Configurable rate limiting middleware to prevent API abuse
- **Graceful Shutdown**: Proper signal handling and cleanup for production deployments
- **UI Refactoring**: Extracted CSS and JavaScript into separate modular files
- **Documentation**: AWS setup guide, test coverage plans, security policy, and contributing guidelines

### Changed
- **Server Architecture**: Enhanced server.py with modular endpoint organization
- **Authentication**: Improved auth middleware with better error handling and test fixtures
- **UI Structure**: Refactored monolithic HTML into maintainable components (css/main.css, js/app.js)

### Fixed
- **Mock AWS Decorator**: Corrected @mock_aws usage across all AWS collector tests
- **Cypher Validation**: Enhanced security with comprehensive query validation and injection prevention
- **Auth Fixture**: Resolved pytest fixture scope issues in test suite
- **Bundle Validation**: Improved error handling in AWS bundle processing

### Security
- Strengthened Cypher query validation to prevent injection attacks
- Added comprehensive security testing coverage
- Implemented rate limiting to prevent abuse

## [0.2.0] - 2024-12-XX

### Added
- Initial multi-cloud architecture refactor
- Modern UI with attack path visualization
- Non-commercial license

## [0.1.0] - Initial Release

### Added
- Core graph analytics engine
- AWS collector integration
- Neo4j database support
- Basic CLI interface
