# Scanner Service Plan

## Context

The `Image` DB table is the single source of truth for scanner configuration. Images are pre-populated separately (schema and seed handled outside the scanner). Multiple scanner instances may run concurrently. Each claims images one by one (up to `batch_size`), scans them concurrently via `asyncio.run(gather(...))`, and persists results per-image immediately. `scan_started_at` protects against stuck scans (crash / hang / OOM) via stale timeout recovery. The scanner loop itself is sync (`BlockingScheduler`); only Trivy subprocess calls use async.

## Existing Models (no changes)

- `app/models/database.py` — `Image`, `CVE`, `ImageCVE`, `ScanStatus`, `Severity`, `FixStatus`
- `app/models/trivy.py` — `ScanResult`, `VulnerabilityDetail`

## Image Lifecycle

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
```

## Multi-Instance Safety: Optimistic Locking

Atomic UPDATE with WHERE guard — only one scanner wins per image:

```python
stmt = (
    update(Image)
    .where(Image.id == candidate_id, Image.scan_status != ScanStatus.SCANNING)
    .values(scan_status=ScanStatus.SCANNING, scan_started_at=now)
)
if session.exec(stmt).rowcount == 0:  # another scanner claimed it
    skip
```

## Files to Create

### 1. `app/scanner/__init__.py`
Empty package init.

### 2. `app/scanner/settings.py` — Scanner Settings

Self-contained settings for the scanner service. `db_url` lives directly here.

```python
class ScannerSettings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="SCANNER_")
    db_url: str = "sqlite:///scanner.db"
    scan_interval_seconds: int = 900      # 15 min rescan interval
    stale_timeout_seconds: int = 600      # 10 min stale timeout
    failed_retry_seconds: int = 300       # 5 min backoff before retrying failed images
    batch_size: int = 5
```

### 3. `app/scanner/container.py` — Scanner Composition Root

Owns the DB engine. Per CLAUDE.md: each service has its own container.

No table creation or seeding — schema is handled separately.

```python
class ScannerContainer:
    def __init__(self, settings: ScannerSettings) -> None:
        self.settings = settings
        self.engine = create_engine(settings.db_url)
        self.trivy_client = TrivyClient()

    def scanner_service(self) -> ScannerService:
        return ScannerService(Session(self.engine), self.trivy_client, self.settings)
```

### 4. `app/scanner/service.py` — Scanner Service

```python
class ScannerService:
    def __init__(self, session: Session, trivy_client: TrivyClient, settings: ScannerSettings) -> None:
```

**Methods:**
- `find_eligible_images() -> list[Image]` — up to `batch_size` eligible images (pending, failed with 5 min backoff, stale scanning, scanned due for rescan)
- `claim_image(image_id: int) -> bool` — optimistic-lock UPDATE
- `async scan_one(image: Image) -> None` — async Trivy call, persist immediately with own session
- `persist_scan_result(image: Image, result: ScanResult) -> None` — upsert CVEs + ImageCVEs, delete stale, update Image
- `run_cycle() -> None` — sync: find → claim one by one → `asyncio.run(gather(...))` for Trivy calls only

### 5. `app/core/clients/trivy.py` — Async Trivy Client

```python
class TrivyClient:
    async def scan(self, image_name: str, image_tag: str) -> ScanResult:
        proc = await asyncio.create_subprocess_exec(
            "trivy", "image", "--format", "json", "--quiet", f"{image_name}:{image_tag}",
            stdout=PIPE, stderr=PIPE,
        )
        stdout, stderr = await proc.communicate()
        # parse JSON → ScanResult
```

### 6. `app/core/clients/database.py` — DB Helpers

Thin helpers: `create_db_engine(url)`, `create_tables(engine)`, `get_session(engine)`.

### 7. `app/core/__init__.py`, `app/core/clients/__init__.py`
Empty package inits.

## Persist Logic (per image, immediately after scan)

Each `scan_one` coroutine persists with its own DB session:
1. Update `Image` metadata (`os_family`, `os_version`, `scan_status=scanned`, `scanned_at=now`)
2. For each vuln: upsert CVE by `cve_id`, upsert ImageCVE by `(image_id, cve_id, package_name)`
3. Delete stale ImageCVEs not in latest scan

## Sync Loop, Async Trivy Only

```python
def run_cycle(self) -> None:
    candidates = self.find_eligible_images()           # sync DB query
    claimed = [img for img in candidates if self.claim_image(img.id)]  # sync, one by one
    if claimed:
        asyncio.run(self._scan_batch(claimed))         # async only for Trivy subprocesses

async def _scan_batch(self, images: list[Image]) -> None:
    await asyncio.gather(*(self.scan_one(img) for img in images))
```

# find_eligible_images
select(Image).where(
    Image.is_active == True,
    or_(
        Image.scan_status == ScanStatus.PENDING,
        # Failed with backoff
        and_(
            Image.scan_status == ScanStatus.FAILED,
            Image.scan_started_at < now - timedelta(seconds=settings.failed_retry_seconds)
        ),
        # Stuck scan recovery
        and_(
            Image.scan_status == ScanStatus.SCANNING,
            Image.scan_started_at < now - timedelta(seconds=settings.stale_timeout_seconds)
        ),
        # Due for rescan
        and_(
            Image.scan_status == ScanStatus.SCANNED,
            Image.scanned_at < now - timedelta(seconds=settings.scan_interval_seconds)
        ),
    )
).limit(settings.batch_size)

DB ops (find, claim, persist) are synchronous via SQLModel Session. Only Trivy subprocess calls are async — that's where the I/O wait lives. The scheduler is a sync `BlockingScheduler`; `asyncio.run` bridges into async for the subprocess gather.

## Tests — `tests/scanner/test_service.py`

Happy-path with SQLite in-memory + mocked async TrivyClient:
- find_eligible_images (pending, failed with 5 min backoff, stale scanning, due-for-rescan, skips inactive/recently-scanned)
- claim_image success + failure (already scanning)
- persist_scan_result (creates CVEs/ImageCVEs, removes stale)
- scan_one success + failure (marks FAILED)
- run_cycle scans a batch

## Verification

```bash
python -m pytest tests/scanner/ -v
```
