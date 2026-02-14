# Contributing to ThreatLoom

Thanks for your interest in contributing! This document provides guidelines for contributing to the ThreatLoom SOC Platform.

## Getting Started

1. **Fork** the repository and clone your fork.
2. Run `setup.bat` (Windows) to create a virtual environment and install dependencies.
3. Create a feature branch: `git checkout -b feature/my-feature`
4. Make your changes.
5. Run tests: `pytest tests/ -v`
6. Commit with a clear message: `git commit -m "feat: add XYZ"`
7. Push and open a Pull Request.

## Project Structure

```
threatloom/
├── models/       # SQLAlchemy ORM models
├── schemas/      # Pydantic request/response schemas
├── auth/         # JWT, RBAC, audit
├── ingestion/    # Log parsers & normalization
├── detection/    # Rule, behavioral, correlation engines
├── response/     # SOAR playbook execution
├── storage/      # Retention lifecycle
├── websocket/    # Real-time streaming
├── api/v1/       # REST API routes
└── utils/        # Helpers & GeoIP
```

## Commit Message Convention

Use [Conventional Commits](https://www.conventionalcommits.org/):

| Prefix | Purpose |
|--------|---------|
| `feat:` | New feature |
| `fix:` | Bug fix |
| `docs:` | Documentation only |
| `refactor:` | Code refactoring (no feature change) |
| `test:` | Adding or updating tests |
| `chore:` | Build process, dependencies |

## Adding Detection Rules

Add YAML files to `rules/` following the format in `rules/default_rules.yaml`. Each rule needs:
- Unique `id`
- `type`: `signature` or `threshold`
- `conditions` (signature) or `threshold` config (threshold)
- `severity`, `mitre_tactic`, `mitre_technique`

## Adding Playbooks

Add YAML files to `playbooks/` following `playbooks/default_playbooks.yaml`. Each playbook needs:
- Unique `id`
- `trigger` with severity and optional attack_types
- Ordered `actions` list
- `cooldown_seconds`

## Code Style

- Python 3.10+
- Type hints on all function signatures
- Async/await for I/O operations
- Docstrings on public classes and functions

## Testing

```bash
pytest tests/ -v
```

Add tests for new features in the `tests/` directory.

## Reporting Issues

Use GitHub Issues. Include:
- Steps to reproduce
- Expected vs actual behavior
- Python version and OS
- Relevant log output
