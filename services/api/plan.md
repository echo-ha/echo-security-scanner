# API Service Plan

## Context

The scanner service is complete (`services/scanner/`). We need a REST API service that reads the same database and exposes vulnerability data. The API runs as a **separate process** from the scanner, sharing the same PostgreSQL database. List endpoints support **offset/limit pagination**.

Import convention: `from core.models.database import ...`, `from services.api.settings import ...` (PYTHONPATH is project root).

## Files to Create

### Shared (`core/`)

1. **`core/exceptions.py`** — `AppError` base + `NotFoundError(404)`

### API Service (`services/api/`)

2. **`services/api/__init__.py`** — empty
3. **`services/api/schemas.py`** — Pydantic response models:
   - `HealthResponse` (status)
   - `SeverityCounts` (critical, high, medium, low, unknown)
   - `ImageSummary` (id, name, tag, os_family, os_version, scan_status, scanned_at, severity_counts, total_cves)
   - `PackageDetail` (package_name, installed_version, fixed_version, fix_status, pkg_class, pkg_type)
   - `CVESummary` (cve_id, severity, cvss_score, title, description, published_date, affected_image_count) — for `GET /api/cves`
   - `ImageCVEDetail` (cve_id, severity, cvss_score, title, description, published_date, package: PackageDetail) — for `GET /api/images/{name}/{tag}/cves`
   - `AffectedImage` (image_id, name, tag, scan_status, scanned_at, package: PackageDetail)
   - `PaginatedResponse[T]` (items, total, offset, limit) — generic wrapper
4. **`services/api/settings.py`** — `ApiSettings(BaseSettings)` with `API_` env prefix: db_url, host, port, default_page_limit(50), max_page_limit(200)
5. **`services/api/service.py`** — `ApiService` with read-only query methods (keep strictly read-only, don't let it grow into a god class):
   - `list_images(offset, limit) -> PaginatedResponse[ImageSummary]` — LEFT JOIN images->image_cves->cves, GROUP BY image with conditional severity counts via `func.count(case(...))`
   - `list_image_cves(name, tag, severity?, offset, limit) -> PaginatedResponse[ImageCVEDetail]` — resolve image (404 if not found), join ImageCVE+CVE, optional severity filter, package detail populated
   - `list_cves(severity?, offset, limit) -> PaginatedResponse[CVESummary]` — JOIN cves->image_cves, GROUP BY cve with `func.count(ImageCVE.image_id)` for `affected_image_count`
   - `list_cve_images(cve_id, offset, limit) -> PaginatedResponse[AffectedImage]` — resolve CVE by cve_id (404 if not found), join ImageCVE->Image, return affected images with package details
6. **`services/api/container.py`** — `ApiContainer`: owns engine, factory for `ApiService`
7. **`services/api/dependencies.py`** — shared `get_service()` placeholder for FastAPI DI override
8. **`services/api/exception_handlers.py`** — `app_error_handler` converts `AppError` to JSON

### Routes (`services/api/routes/`)

9. **`services/api/routes/__init__.py`** — empty
10. **`services/api/routes/health.py`** — `GET /health` checks DB connectivity via `SELECT 1`, returns `HealthResponse(status="ok")`. If DB is down, returns 503.
11. **`services/api/routes/images.py`** — thin handlers:
    - `GET /api/images` (offset, limit query params)
    - `GET /api/images/{image_name}/{tag}/cves` (severity, offset, limit query params)
12. **`services/api/routes/cves.py`** — thin handlers:
    - `GET /api/cves` (severity, offset, limit query params)
    - `GET /api/cves/{cve_id}/images` (offset, limit query params)

### Entry Point

13. **`services/api/__main__.py`** — `create_app()` factory + `uvicorn.run()`:
    - Registers exception handlers
    - Wires `app.dependency_overrides[get_service] = container.api_service`
    - Includes all routers

### Docker

14. **Modify `docker-compose.yml`** — add `api` service:
    - Same `build: .`, different `command: python -m services.api`
    - Depends on db (healthy) + seed (completed)
    - `API_DB_URL: postgresql://scanner:scanner@db:5432/scanner`
    - Expose port 8000

### Tests

15. **`tests/api/__init__.py`** — empty
16. **`tests/api/test_service.py`** — happy-path tests with in-memory SQLite:
    - `test_list_images_with_severity_counts` — seed images with CVEs, verify counts
    - `test_list_images_pagination` — verify offset/limit/total
    - `test_list_image_cves` — verify CVEs returned with package details
    - `test_list_image_cves_severity_filter` — filter by severity
    - `test_list_image_cves_not_found` — 404 for unknown image
    - `test_list_cves` — verify CVEs returned with affected_image_count
    - `test_list_cve_images` — verify affected images with package details
    - `test_list_cve_images_not_found` — 404 for unknown CVE

## Key Query Logic

**Pagination `total` count**: Always use a separate `COUNT(*)` query over the full filtered result set, not `len(items)`. Two queries approach (count + data) is simpler and fine for this scale.

**`list_images`** (most complex): Uses `outerjoin` so images with 0 CVEs still appear. Severity counts via `func.count(case((CVE.severity == X, 1)))` -- count ignores NULLs, giving per-severity breakdown.

**`list_image_cves`**: Joins ImageCVE+CVE for a specific image_id, returns tuples `(CVE, ImageCVE)` to populate both CVE fields and package detail in one query.

**`list_cves`**: LEFT JOIN cves->image_cves, GROUP BY cve, with `func.count(distinct(ImageCVE.image_id))` for `affected_image_count`. Uses distinct count since same image+cve can have multiple package entries.

**`list_cve_images`**: Joins ImageCVE+Image for a specific cve_id. Note: same image can appear multiple times if the CVE affects multiple packages (correct behavior per unique constraint on image_id+cve_id+package_name).

## Verification

```bash
python -m pytest tests/api/ -v
API_DB_URL=postgresql://scanner:scanner@localhost:5432/scanner python -m services.api
docker compose up --build api
```
