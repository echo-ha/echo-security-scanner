# Trivy JSON Report Structure

How to read a Trivy `--format json` output, from top to bottom.

## Visual Overview

```
{
  SchemaVersion ─── always 2
  ArtifactName  ─── "nginx:1.19" (the image you scanned)
  ArtifactType  ─── "container_image"
  Metadata      ─── image metadata (OS, layers, config)
  │
  Results[]     ─── list of scan TARGETS (one per package class)
  │
  ├── Result[0]: "nginx:1.19 (debian 10.9)"    ← OS packages
  │   ├── Class: "os-pkgs"
  │   ├── Type:  "debian"
  │   ├── Packages[]          ← all packages found (even safe ones)
  │   └── Vulnerabilities[]   ← only the vulnerable ones
  │       ├── Vuln[0] ─── CVE-2022-32221 in curl
  │       ├── Vuln[1] ─── CVE-2021-22946 in curl
  │       └── ...
  │
  └── Result[1]: "Python"                       ← language packages (if any)
      ├── Class: "lang-pkgs"
      ├── Type:  "python-pkg"
      ├── Packages[]
      └── Vulnerabilities[]
}
```

**Key insight:** An image can have **multiple Results** -- one for OS-level packages and
optionally more for language-level packages (pip, npm, go modules, etc.).
`alpine:3.12` has 1 Result (os-pkgs only), `python:3.8-slim` has 2 (os-pkgs + python-pkg).

---

## Level 1: Root Object

| Field | Type | What it is |
|---|---|---|
| `SchemaVersion` | int | Always `2` |
| `ArtifactName` | string | Image reference, e.g. `"nginx:1.19"` |
| `ArtifactType` | string | `"container_image"` |
| `Metadata` | object | OS info, image layers, Docker config |
| `Results` | array | **The main data** -- one entry per scan target |

### Metadata (what we care about)

```json
"Metadata": {
  "OS": {
    "Family": "debian",     ← OS type (debian, alpine, ubuntu...)
    "Name": "10.9",         ← OS version
    "EOSL": true            ← end-of-support-life flag (optional)
  },
  "ImageID": "sha256:...",
  "RepoDigests": ["nginx@sha256:..."]   ← immutable image digest
}
```

We extract: `OS.Family`, `OS.Name`. The rest is informational.

---

## Level 2: Results Array

Each Result = one **scan target** within the image.

| Field | Type | What it is |
|---|---|---|
| `Target` | string | Human-readable label, e.g. `"nginx:1.19 (debian 10.9)"` or `"Python"` |
| `Class` | string | `"os-pkgs"` or `"lang-pkgs"` |
| `Type` | string | Package manager: `"debian"`, `"alpine"`, `"python-pkg"`, `"npm"`, `"gomod"`, etc. |
| `Packages` | array | **All** packages found in this target (including safe ones) |
| `Vulnerabilities` | array or null | **Only vulnerable** packages. `null` if no vulns found in this target. |

### Class + Type combinations you'll see:

| Class | Type | Meaning |
|---|---|---|
| `os-pkgs` | `debian` | Debian apt packages |
| `os-pkgs` | `alpine` | Alpine apk packages |
| `os-pkgs` | `ubuntu` | Ubuntu apt packages |
| `lang-pkgs` | `python-pkg` | Python pip packages |
| `lang-pkgs` | `node-pkg` | Node.js npm packages |
| `lang-pkgs` | `gomod` | Go modules |

---

## Level 3: Vulnerability Object

Each entry in `Vulnerabilities[]` is one CVE affecting one package.

### Fields we extract (for our database):

| Field | Type | Example | Notes |
|---|---|---|---|
| `VulnerabilityID` | string | `"CVE-2022-32221"` | The CVE identifier |
| `Severity` | string | `"CRITICAL"` | `CRITICAL` > `HIGH` > `MEDIUM` > `LOW` > `UNKNOWN` |
| `PkgName` | string | `"curl"` | Which package is affected |
| `InstalledVersion` | string | `"7.64.0-4+deb10u2"` | Version in the image |
| `FixedVersion` | string or absent | `"7.64.0-4+deb10u4"` | Version that fixes it. Missing = no fix yet. |
| `Status` | string | `"fixed"` | `fixed`, `affected`, `will_not_fix`, `fix_deferred`, `end_of_life` |
| `Title` | string | `"curl: POST following PUT confusion"` | Short description |
| `Description` | string | (long text) | Full CVE description |

### Fields available but we skip:

| Field | What it is | Why we skip |
|---|---|---|
| `PkgID` | `"curl@7.64.0-4+deb10u2"` | Redundant with PkgName + InstalledVersion |
| `PkgIdentifier.PURL` | Package URL standard | More detail than we need |
| `Layer` | Which image layer introduced it | Not needed for our API |
| `SeveritySource` | Who assigned the severity (`"nvd"`) | Nice-to-have, not required |
| `PrimaryURL` | Link to advisory | Nice-to-have |
| `DataSource` | Which vuln DB matched | Internal to Trivy |
| `CweIDs` | Weakness category (`["CWE-200"]`) | Nice-to-have |
| `VendorSeverity` | Severity per vendor (nvd, redhat, etc.) | Map of ints, complex |
| `CVSS` | Score details per vendor | We could extract `V3Score` from here |
| `References` | List of URLs | Too many to store |
| `PublishedDate` | When CVE was published | Nice-to-have |
| `LastModifiedDate` | When CVE was last updated | Nice-to-have |

### CVSS scores (nested)

```json
"CVSS": {
  "nvd": {
    "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    "V3Score": 9.8        ← this is the numeric score we'd extract
  },
  "redhat": {
    "V3Vector": "...",
    "V3Score": 4.8         ← same CVE, different vendor opinion
  }
}
```

Multiple vendors can score the same CVE differently. We grab the first `V3Score` we find
(typically NVD).

---

## Important Gotchas

1. **`Vulnerabilities` can be `null`** -- not an empty list, literally `null` in the JSON.
   Always use `result.get("Vulnerabilities") or []`.

2. **Same CVE, multiple packages** -- One CVE can appear multiple times in the same Result
   if it affects multiple packages (e.g. CVE-2021-37600 hits `bsdutils`, `fdisk`, `libblkid1`,
   `mount`, `util-linux` -- all from the same source package `util-linux`).

3. **Same CVE, multiple images** -- Debian-based images share many of the same system packages,
   so the same CVE will appear when scanning `nginx:1.19` and `python:3.8-slim`.

4. **`FixedVersion` is optional** -- If the status is `affected` or `will_not_fix`, there is
   no `FixedVersion` key in the JSON.

5. **`Packages` vs `Vulnerabilities`** -- `Packages` lists *everything* installed.
   `Vulnerabilities` lists only the *vulnerable* ones. We only care about `Vulnerabilities`.
