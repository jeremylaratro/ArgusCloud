# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
