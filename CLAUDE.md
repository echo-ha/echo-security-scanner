# CLAUDE.md

## Principles

KISS, YAGNI, SOLID. No hardcoded credentials. Validate inputs. Handle errors.

## User Preferences

### Data Models

Use Pydantic `BaseModel` for all data model objects - request/response schemas, domain entities, DTOs. Place in `app/schemas/`.

### Git

If not a git repo, run `git init` and create appropriate `.gitignore`.

### Configuration

Use `pydantic-settings` with composition root pattern:

1. Add settings class to `app/core/settings.py` with env prefix
2. Nest under `AppSettings` via `Field(default_factory=...)`
3. Add client to `app/core/clients/` if needed
4. Wire in `app/core/container.py` - only place dependencies are instantiated
5. Services require dependencies via constructor - no optional defaults, no singletons
6. Add env vars to `.env` and `.env.example`
7. Update `docker-compose.yml` if config relates to a service

```
app/
├── core/
│   ├── settings.py      # Pydantic settings
│   ├── container.py     # Composition root
│   └── clients/         # External service clients
└── services/            # Business logic
```

### API Routes

Keep handlers thin - validate input, call service, return response. No business logic in routes.

```
app/api/
├── routes/              # Route handlers by domain
├── dependencies.py      # FastAPI Depends functions
└── exception_handlers.py
```

### Exceptions

Define in `app/core/exceptions.py`. Inherit from base `AppError`. Handlers in `app/api/exception_handlers.py`.

Never silently `pass` or swallow exceptions. If something critical fails, raise an exception and handle it explicitly.

### Testing

Use pytest. Write a few happy-path tests for core logic — enough to prove it works, not full coverage. Skip edge cases unless time permits. Run tests to verify before submitting. Structure: `tests/` mirroring `app/`.

### Logging

Use stdlib `logging` to console. Keep it simple - no files, no complex formatting.

### Type Hints

Always use type hints. `T | None` over `Optional[T]`. Return types mandatory.

### Docstrings

Keep them short - one line if possible. Type hints replace parameter documentation. Skip for obvious methods.

### Dependencies

Use `requirements.txt` for simplicity. Skip `pyproject.toml` unless project needs packaging.

### Attributes

Never use `getattr`/`setattr` - access attributes directly. Code should be explicit and type-safe.

### Enums

Define near where used. If shared across modules, put in `app/core/enums.py`.

### Database

Use SQLModel (simpler, Pydantic-compatible). SQLAlchemy if specified or more control needed. Inject session via container. Queries live in services, not routes. Skip migrations unless asked.

```
app/
├── core/
│   └── clients/
│       └── database.py    # Engine, session factory
├── models/                 # SQLModel table definitions
└── services/               # Queries here
```

### Docker

Create `docker-compose.yml` immediately if external services needed. `Dockerfile` when deployment discussed.

### README

Minimal: what it does, how to run, env vars needed.
