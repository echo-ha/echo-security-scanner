# Container Security Scanner

A backend service that periodically scans Docker container images for CVE vulnerabilities using [Trivy](https://trivy.dev/), stores results in PostgreSQL, and exposes a REST API for querying security data.

## Prerequisites

- Docker & Docker Compose
- (Optional) Python 3.12+ if running tests locally

## Quick Start

```bash
docker compose up -d --build
```

This starts five services:

| Service     | Description                          | Port  |
|-------------|--------------------------------------|-------|
| **db**      | PostgreSQL 16                        | 5432  |
| **seed**    | One-shot: creates tables & seeds images | —  |
| **trivy**   | Trivy vulnerability DB server        | 4954  |
| **scanner** | Scans images every 15 minutes        | —     |
| **api**     | REST API (FastAPI + Uvicorn)         | 8000  |

The scanner runs an initial full scan on startup, then rescans every 15 minutes. First run takes a few minutes while Trivy downloads its vulnerability database.

Check that everything is healthy:

```bash
docker compose ps
curl http://localhost:8000/health
# {"status":"ok"}
```

## Scanned Images

nginx:1.19, postgres:12, redis:6.0, node:14-alpine, python:3.8-slim, alpine:3.12, ubuntu:20.04, mysql:8.0, mongo:4.4, httpd:2.4

## API Endpoints

All list endpoints support pagination via `offset` (default 0) and `limit` (default 50, max 200).

---

### GET /health

Health check — verifies DB connectivity.

```bash
curl http://localhost:8000/health
```

```json
{"status": "ok"}
```

---

### GET /api/images

List all scanned images with aggregated CVE severity counts.

```bash
curl http://localhost:8000/api/images?limit=2
```

```json
{
  "items": [
    {
      "id": 1,
      "name": "nginx",
      "tag": "1.19",
      "os_family": "debian",
      "os_version": "10.9",
      "scan_status": "scanned",
      "scanned_at": "2026-02-10T22:20:37.775429",
      "severity_counts": {
        "critical": 5,
        "high": 32,
        "medium": 28,
        "low": 61,
        "unknown": 0
      },
      "total_cves": 126
    },
    {
      "id": 2,
      "name": "postgres",
      "tag": "12",
      "os_family": "debian",
      "os_version": "12.9",
      "scan_status": "scanned",
      "scanned_at": "2026-02-10T22:19:44.723102",
      "severity_counts": {
        "critical": 0,
        "high": 3,
        "medium": 12,
        "low": 33,
        "unknown": 0
      },
      "total_cves": 48
    }
  ],
  "total": 10,
  "offset": 0,
  "limit": 2
}
```

---

### GET /api/images/{image_name}/{tag}/cves

List CVEs for a specific image. Optionally filter by severity.

```bash
curl "http://localhost:8000/api/images/nginx/1.19/cves?severity=CRITICAL&limit=2"
```

```json
{
  "items": [
    {
      "cve_id": "CVE-2026-0861",
      "severity": "CRITICAL",
      "cvss_score": 8.1,
      "title": "glibc: Integer overflow in memalign leads to heap corruption",
      "description": "Passing too large an alignment to the memalign...",
      "published_date": "2026-01-14T21:15:52.617000",
      "package": {
        "package_name": "libc-bin",
        "installed_version": "2.31-13+deb11u5",
        "fixed_version": "2.31-13+deb11u12",
        "fix_status": "FIXED",
        "pkg_class": "os-pkgs",
        "pkg_type": "debian"
      }
    }
  ],
  "total": 5,
  "offset": 0,
  "limit": 2
}
```

---

### GET /api/cves

List all unique CVEs across all images with affected image count. Optionally filter by severity.

```bash
curl "http://localhost:8000/api/cves?severity=CRITICAL&limit=2"
```

```json
{
  "items": [
    {
      "cve_id": "CVE-2026-0861",
      "severity": "CRITICAL",
      "cvss_score": 8.1,
      "title": "glibc: Integer overflow in memalign leads to heap corruption",
      "description": "Passing too large an alignment to the memalign...",
      "published_date": "2026-01-14T21:15:52.617000",
      "affected_image_count": 7
    }
  ],
  "total": 12,
  "offset": 0,
  "limit": 2
}
```

---

### GET /api/cves/{cve_id}/images

List all images affected by a specific CVE, including package details.

```bash
curl "http://localhost:8000/api/cves/CVE-2026-0861/images?limit=2"
```

```json
{
  "items": [
    {
      "image_id": 1,
      "name": "nginx",
      "tag": "1.19",
      "scan_status": "scanned",
      "scanned_at": "2026-02-10T22:20:37.775429",
      "package": {
        "package_name": "libc-bin",
        "installed_version": "2.31-13+deb11u5",
        "fixed_version": "2.31-13+deb11u12",
        "fix_status": "FIXED",
        "pkg_class": "os-pkgs",
        "pkg_type": "debian"
      }
    }
  ],
  "total": 7,
  "offset": 0,
  "limit": 2
}
```

---

## Database Schema

PostgreSQL with three tables:

```
┌──────────────────────┐       ┌──────────────────────┐
│       images         │       │        cves           │
├──────────────────────┤       ├───────────────────────┤
│ id          PK       │       │ id           PK       │
│ name        text     │       │ cve_id       unique   │
│ tag         text     │       │ severity     enum     │
│ is_active   bool     │       │ cvss_score   float    │
│ os_family   text     │       │ title        text     │
│ os_version  text     │       │ description  text     │
│ scan_status enum     │       │ published_date timestz│
│ scan_started_at      │       │ created_at   timestz  │
│ scanned_at  timestz  │       │ updated_at   timestz  │
│                      │       └───────────┬───────────┘
│ created_at  timestz  │                   │
│ updated_at  timestz  │                   │
└──────────┬───────────┘                   │
           │                               │
           │        ┌──────────────────┐   │
           └───────►│   image_cves     │◄──┘
                    ├──────────────────┤
                    │ id          PK   │
                    │ image_id    FK   │
                    │ cve_id      FK   │
                    │ package_name     │
                    │ installed_version│
                    │ fixed_version    │
                    │ fix_status  enum │
                    │ pkg_class        │
                    │ pkg_type         │
                    │ created_at       │
                    └──────────────────┘
                    UNIQUE(image_id, cve_id, package_name)
```

- **images**: One row per container image. `scan_status` tracks lifecycle: `pending` → `scanning` → `scanned` / `failed`.
- **cves**: One row per unique CVE across all images. Deduplicated by `cve_id`.
- **image_cves**: Junction table linking images to CVEs at the package level. The same CVE can appear multiple times for one image if it affects different packages.

### Design Rationale

- **Why CVEs are a separate table** — CVEs carry rich shared metadata (severity, CVSS, title, description, published date). Without deduplication this would be repeated across every `image_cves` row, causing update anomalies and wasted storage.
- **Why packages are NOT a separate table** — package info (installed version, fixed version, fix status) is specific to each image-CVE pair. No shared metadata to deduplicate; a packages table would just be `id` + `name` with all version columns still on the junction table. YAGNI.
- **Why UNIQUE(image_id, cve_id, package_name)** — the same CVE can affect multiple packages on a single image (e.g., both `libc-bin` and `libc6` share vulnerable glibc code). All three columns are needed.

## Architecture

```
┌───────────┐  every 15 min   ┌─────────────┐   async scan   ┌───────┐
│ Scheduler ├────────────────►│  Scanner     ├───────────────►│ Trivy │
│(APScheduler)│               │  Service     │◄───────────────│Server │
└───────────┘                 └──────┬───────┘   JSON result  └───────┘
                                     │
                              upsert │ CVEs
                                     ▼
                              ┌──────────────┐    ┌───────────┐
                              │  PostgreSQL  │◄───┤  REST API │◄── GET /api/...
                              └──────────────┘    │ (FastAPI) │
                                                  └───────────┘
```

Key design decisions:

- **Separate scanner and API services** — clean separation of concerns;
  scanner writes, API reads. Can scale and deploy independently.
- **Optimistic locking for image claiming** — atomic UPDATE with WHERE
  guard enables horizontal scaling without Redis or distributed locks.
  Postgres is already in the stack.
- **Trivy client/server mode** — centralizes the vulnerability DB in one
  process. Eliminates BoltDB (the embedded db trivy uses) file lock contention, enabling parallel scans
  via asyncio.gather.
- **Async Trivy calls, sync DB** — Trivy subprocess is the I/O bottleneck,
  not DB writes. Keeps DB logic simple with synchronous SQLModel sessions.
- **Stale lock recovery** — images stuck in "scanning" for >10 min are
  automatically reclaimed. Protects against scanner crashes without manual
  intervention.
- **Stale CVE cleanup** — vulnerabilities no longer in the latest scan are
  deleted from image_cves. Ensures the API always reflects current state.

## Configuration

All settings via environment variables:

| Variable                       | Default                 | Description                    |
|--------------------------------|-------------------------|--------------------------------|
| `SCANNER_DB_URL`               | `sqlite:///scanner.db`  | Database connection string     |
| `SCANNER_TRIVY_SERVER_URL`     | `http://trivy:4954`     | Trivy server URL               |
| `SCANNER_SCAN_INTERVAL_SECONDS`| `900`                   | Rescan interval (15 min)       |
| `SCANNER_STALE_TIMEOUT_SECONDS`| `600`                   | Stale lock timeout (10 min)    |
| `SCANNER_FAILED_RETRY_SECONDS` | `300`                   | Failed retry backoff (5 min)   |
| `SCANNER_BATCH_SIZE`           | `5`                     | Images per scan batch          |
| `API_DB_URL`                   | `sqlite:///scanner.db`  | Database connection (API)      |
| `API_HOST`                     | `0.0.0.0`              | API listen address             |
| `API_PORT`                     | `8000`                  | API listen port                |

## Running Tests

```bash
pip install -r requirements.txt
python -m pytest tests/ -v
```

Tests use in-memory SQLite — no external services needed.

## Project Structure

```
core/
  clients/trivy.py        # Async Trivy CLI wrapper
  models/database.py      # SQLModel table definitions
  models/trivy.py         # Pydantic models for Trivy output
  exceptions.py           # Application error hierarchy
services/
  scanner/
    service.py            # Find, claim, scan, persist logic
    scheduler.py          # APScheduler entry point
    container.py          # Composition root (DI)
    settings.py           # Scanner configuration
    Dockerfile
  api/
    service.py            # Read-only query service
    schemas.py            # Pydantic response models
    routes/               # Thin FastAPI route handlers
    container.py          # Composition root (DI)
    exception_handlers.py
    settings.py           # API configuration
    Dockerfile
scripts/
  seed.py                 # DB init + image seeding
tests/
  scanner/test_service.py # 17 scanner tests
  api/test_service.py     # 9 API tests
docker-compose.yml
requirements.txt
```
