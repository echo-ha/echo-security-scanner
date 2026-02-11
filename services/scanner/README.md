# Scanner Service

Background service that continuously scans container images for CVE vulnerabilities using [Trivy](https://github.com/aquasecurity/trivy).

## Architecture

```
┌──────────────────────────────────────────────────────────┐
│  Scanner Service                                         │
│                                                          │
│  ┌─────────────┐    ┌──────────────────────────────────┐ │
│  │ APScheduler │───>│         ScannerService           │ │
│  │ (interval)  │    │                                  │ │
│  └─────────────┘    │  find_eligible ─> claim ─> scan  │ │
│                     │       │             │        │    │ │
│                     │       ▼             ▼        ▼    │ │
│                     │   ┌──────┐   ┌──────┐  ┌───────┐ │ │
│                     │   │  DB  │   │  DB  │  │ Trivy │ │ │
│                     │   │ read │   │ lock │  │ async │ │ │
│                     │   └──────┘   └──────┘  └───┬───┘ │ │
│                     │                            │      │ │
│                     │                  persist <──┘      │ │
│                     │                     │              │ │
│                     │                     ▼              │ │
│                     │              ┌────────────┐        │ │
│                     │              │ DB upsert  │        │ │
│                     │              │ CVE + join │        │ │
│                     │              └────────────┘        │ │
│                     └──────────────────────────────────┘ │
│                                                          │
│  ┌─────────────┐                                         │
│  │  Container   │ ← owns Engine + TrivyClient + Settings │
│  └─────────────┘                                         │
└──────────────────────────────────────────────────────────┘
         │                                    │
         ▼                                    ▼
   ┌───────────┐                      ┌──────────────┐
   │ PostgreSQL │                      │ Trivy Server │
   └───────────┘                      └──────────────┘
```

## Image Lifecycle

Each image transitions through states managed by the scanner:

```
┌─────────┐  claim   ┌──────────┐  success  ┌─────────┐
│ PENDING │────────>│ SCANNING │──────────>│ SCANNED │──┐
└─────────┘          └──────────┘            └─────────┘  │
     ▲                    │                       │       │ rescan
     │                    │ failure               │       │ (15 min)
     │                    ▼                       ◄───────┘
     │              ┌──────────┐
     │              │  FAILED  │     stale scan_started_at
     │              └──────────┘     also re-enters eligibility
     │                    │
     └────────────────────┘
           (5 min backoff)
```

## Design Decisions

### Optimistic Locking for Multi-Instance Safety

Multiple scanner instances can run concurrently. Instead of distributed locks (Redis, ZooKeeper), the scanner uses an **atomic SQL UPDATE with a WHERE guard**:

```sql
UPDATE images
SET scan_status = 'scanning', scan_started_at = now()
WHERE id = :id AND (scan_status != 'scanning' OR scan_started_at IS NULL OR scan_started_at <= :stale_cutoff)
```

If `rowcount == 0`, another instance already claimed the image. This is lock-free, requires no external infrastructure, and naturally handles stale scans (crashed scanners) via the timeout condition.

### Sync Loop + Async Scans

The scheduler and DB operations are synchronous — there's no benefit to async DB access at this scale. Only the Trivy subprocess calls are async, using `asyncio.gather()` to scan a batch of images concurrently. This avoids the complexity of a fully async architecture while still parallelizing the I/O-bound work.

### Stale Image Cleanup

After persisting new results, any `ImageCVE` records not seen in the latest scan are deleted. This ensures removed vulnerabilities (patched upstream) are reflected immediately rather than accumulating stale data.

## Project Structure

```
services/scanner/
├── __main__.py       # Entry point — APScheduler + immediate first run
├── scheduler.py      # APScheduler wiring
├── container.py      # Composition root: Engine + TrivyClient → ScannerService
├── service.py        # Core logic: find → claim → scan → persist
├── settings.py       # Pydantic-settings with SCANNER_ env prefix
└── Dockerfile

core/                 # Shared across services
├── clients/trivy.py  # Async subprocess wrapper around trivy CLI
├── models/database.py# SQLModel tables: Image, CVE, ImageCVE
└── models/trivy.py   # Pydantic models for Trivy JSON parsing
```

## Configuration

All settings use the `SCANNER_` environment variable prefix.

| Variable | Default | Description |
|---|---|---|
| `SCANNER_DB_URL` | `sqlite:///scanner.db` | Database connection string |
| `SCANNER_TRIVY_SERVER_URL` | `http://trivy:4954` | Trivy server URL |
| `SCANNER_SCAN_INTERVAL_SECONDS` | `900` | Rescan interval (15 min) |
| `SCANNER_STALE_TIMEOUT_SECONDS` | `600` | Timeout for stuck scans (10 min) |
| `SCANNER_FAILED_RETRY_SECONDS` | `300` | Backoff before retrying failed scans |
| `SCANNER_BATCH_SIZE` | `5` | Max images scanned concurrently per cycle |

## Run

```bash
# Standalone
SCANNER_DB_URL=postgresql://scanner:scanner@localhost:5432/scanner \
SCANNER_TRIVY_SERVER_URL=http://localhost:4954 \
python -m services.scanner

# Docker (starts all dependencies)
docker compose up scanner
```

## Tests

```bash
pytest tests/scanner/ -v
```

Tests use in-memory SQLite and a mocked TrivyClient. Coverage includes the full lifecycle: eligibility filtering, optimistic claim races, scan result persistence with deduplication, and failure handling.
