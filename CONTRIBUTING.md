# Contributing to aumos-finserv-overlay

## Getting Started

```bash
git clone <repo-url>
cd aumos-finserv-overlay
pip install -e ".[dev]"
cp .env.example .env
make docker-run
make migrate
```

## Development Workflow

1. Create a feature branch: `feature/`, `fix/`, or `docs/`
2. Make changes following the hexagonal architecture
3. Run `make lint` and `make typecheck` before committing
4. Write tests for new services in `tests/`
5. Commit with conventional commit format

## Compliance Domain Guidelines

When adding new compliance features:
- Add enums to `api/schemas.py` before writing models
- Add Protocol interface to `core/interfaces.py` for all adapters
- Implement business logic in `core/services.py` — no framework imports
- Add routes to `api/router.py` as thin delegation layers
- Add repository method to `adapters/repositories.py`
- Publish a Kafka event for every state-changing operation

## Code Style

- Python type hints required on all function signatures
- `ruff` for linting and formatting (line length: 120)
- `mypy` strict mode
- Conventional commits: `feat:`, `fix:`, `refactor:`, `docs:`, `test:`

## Regulatory Accuracy

Changes touching compliance logic (SOX, SR 11-7, PCI DSS, DORA) must reference
the relevant regulatory text in PR descriptions. Risk thresholds are configurable
via Settings — do not hardcode them in service logic.
