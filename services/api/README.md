# API Service

Read-only REST API for querying vulnerability scan results. Built with FastAPI.

## Architecture

```
┌──────────────────────────────────────────────────────┐
│  API Service                                         │
│                                                      │
│  ┌────────────────────────────────────────────────┐  │
│  │  FastAPI App                                   │  │
│  │                                                │  │
│  │  Routes (thin handlers)                        │  │
│  │  ┌──────────┐ ┌──────────┐ ┌───────────────┐  │  │
│  │  │ /health  │ │ /images  │ │ /cves         │  │  │
│  │  └────┬─────┘ └────┬─────┘ └──────┬────────┘  │  │
│  │       │             │              │           │  │
│  │       │      ┌──────▼──────────────▼────────┐  │  │
│  │       │      │       ApiService             │  │  │
│  │       │      │  (read-only query methods)   │  │  │
│  │       │      └──────────────┬───────────────┘  │  │
│  │       │                     │                  │  │
│  └───────┼─────────────────────┼──────────────────┘  │
│          │                     │                     │
│  ┌───────▼─────────────────────▼───────────────────┐ │
│  │             SQLAlchemy Engine                    │ │
│  └─────────────────────┬───────────────────────────┘ │
│                        │                             │
│  ┌─────────────┐       │                             │
│  │  Container   │ ← owns Engine + Settings           │
│  └─────────────┘                                     │
└────────────────────────┼─────────────────────────────┘
                         │
                         ▼
                   ┌───────────┐
                   │ PostgreSQL │ (shared with Scanner)
                   └───────────┘
```

## Database Schema

The API reads from three tables populated by the Scanner service:

```
┌──────────────┐       ┌──────────────┐       ┌──────────────┐
│   images     │       │  image_cves  │       │    cves      │
├──────────────┤       ├──────────────┤       ├──────────────┤
│ id (PK)      │──┐    │ id (PK)      │    ┌──│ id (PK)      │
│ name         │  └──>>│ image_id(FK) │    │  │ cve_id (UQ)  │
│ tag          │       │ cve_id  (FK) │<<──┘  │ severity     │
│ scan_status  │       │ package_name │       │ cvss_score   │
│ scanned_at   │       │ installed_ver│       │ title        │
│ os_family    │       │ fixed_version│       │ description  │
│ os_version   │       │ fix_status   │       │ published_date│
└──────────────┘       │ pkg_class    │       └──────────────┘
                       │ pkg_type     │
  UQ(name, tag)        └──────────────┘
                       UQ(image_id, cve_id, package_name)
```

A single CVE can affect multiple images, and the same image+CVE pair can appear multiple times if different packages are affected — hence the three-column unique constraint on the junction table.

## Endpoints

| Method | Path | Description |
|---|---|---|
| `GET` | `/health` | DB connectivity check (returns 503 if unavailable) |
| `GET` | `/api/images` | List images with severity count breakdown per image |
| `GET` | `/api/images/{image_name}/{tag}/cves` | CVEs for a specific image |
| `GET` | `/api/cves` | All unique CVEs with affected image count |
| `GET` | `/api/cves/{cve_id}/images` | Images affected by a specific CVE |

**Pagination**: All list endpoints accept `?offset=` and `?limit=` (default 50, max 200).
**Filtering**: Image CVEs and CVE list accept `?severity=CRITICAL|HIGH|MEDIUM|LOW`.

## Design Decisions

### Thin Routes, Fat Service

Route handlers only validate input and call the service layer — zero business logic in routes. This keeps the HTTP layer swappable and the query logic independently testable (tests hit `ApiService` directly with an in-memory SQLite DB, no HTTP overhead).

### Composition Root Pattern

Dependencies are wired in `ApiContainer`, not scattered across modules. The container owns the SQLAlchemy engine and provides factory methods for services. This makes the dependency graph explicit and avoids global state.

```python
# container.py — the entire DI setup
class ApiContainer:
    def __init__(self, settings: ApiSettings):
        self.engine = create_engine(settings.db_url)

    def api_service(self) -> ApiService:
        return ApiService(self.engine)
```

### Severity Aggregation in SQL

The `GET /api/images` endpoint returns per-severity CVE counts. Instead of fetching all CVEs and counting in Python, this is done in a single SQL query using conditional aggregation:

```sql
SELECT image.*,
       COUNT(CASE WHEN cve.severity = 'CRITICAL' THEN 1 END) as critical,
       COUNT(CASE WHEN cve.severity = 'HIGH' THEN 1 END) as high,
       ...
FROM images LEFT JOIN image_cves LEFT JOIN cves
GROUP BY image.id
```

The `LEFT JOIN` ensures images with zero CVEs still appear in results.

### Separate Count Query for Pagination

Pagination uses a two-query approach: one `COUNT(*)` for the total, one for the page of data. This is simpler than window functions, and at this scale the overhead is negligible. The response includes `total`, `offset`, and `limit` so clients can calculate pages.

## Project Structure

```
services/api/
├── __main__.py           # App factory + uvicorn entry point
├── container.py          # Composition root: Engine → ApiService
├── service.py            # Read-only query methods (all business logic)
├── schemas.py            # Pydantic response models
├── settings.py           # Pydantic-settings with API_ env prefix
├── exception_handlers.py # AppError → JSON response conversion
├── routes/
│   ├── health.py         # GET /health
│   ├── images.py         # GET /api/images, /api/images/{name}/{tag}/cves
│   └── cves.py           # GET /api/cves, /api/cves/{cve_id}/images
└── Dockerfile
```

## Configuration

All settings use the `API_` environment variable prefix.

| Variable | Default | Description |
|---|---|---|
| `API_DB_URL` | `postgresql://scanner:scanner@localhost:5432/scanner` | Database connection string |
| `API_HOST` | `0.0.0.0` | Server bind address |
| `API_PORT` | `8000` | Server port |
| `API_DEFAULT_PAGE_LIMIT` | `50` | Default pagination size |
| `API_MAX_PAGE_LIMIT` | `200` | Maximum allowed page size |

## Run

```bash
# Standalone
API_DB_URL=postgresql://scanner:scanner@localhost:5432/scanner \
python -m services.api

# Docker (starts all dependencies)
docker compose up api
```

## Tests

```bash
pytest tests/api/ -v
```

Tests use in-memory SQLite and call `ApiService` directly. Coverage includes pagination, severity filtering, aggregation correctness, and 404 handling for unknown images/CVEs.
