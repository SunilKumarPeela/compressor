# Point v8.30.3 Security Review Addendum

Addendum date: 2026-09-10

Point v8.30.3 adds the Balanced encoder only. It retains the PFC1 token format,
the same decoder validation, CRC32 verification, block and file limits, atomic
publication, DPAPI ordering, and raw fallback documented below. Balanced mode
uses a bounded eight-candidate hash history per 1 MiB block; decompression does
not allocate this search structure. The v8.30.2 findings therefore remain
applicable, supplemented by Fast-versus-Balanced round-trip and size tests.

## Point v8.30.2 Security Review Addendum

Addendum date: 2026-09-10

The v8.30.1 conclusions below remain applicable to unchanged components. Point
v8.30.2 adds a new compression boundary before DPAPI protection and a separate
user-invoked `.pfc` file workflow. The codec uses bounded 1 MiB blocks, raw
fallback, checked lengths and back-references, per-block CRC32 verification, a
2 GiB file limit, background execution, and atomic destination publication.
Regression coverage now includes multi-megabyte buffers, malformed headers,
multiple corruption positions, truncation, the 65,536-byte distance boundary,
the 259-byte match boundary, streaming file round trips, and the complete
compression-plus-DPAPI integration path on Windows. CI now runs these tests,
verifies release metadata and installer output, and performs CodeQL C++ static
analysis before publishing the installer artifact.

CRC32 provides accidental-corruption detection, not authentication. `.pfc`
archives are compressed but not encrypted; DPAPI protection continues to apply
only to Point's protected workspace/configuration path.

## Prior Point v8.30.1 Security Review

Review date: 2026-09-04

## What Point does

Point is a local Windows data workspace for CSV, XLS, and XLSX reports.
It imports worksheets into bounded local datasets, normalizes headings and
identity values, discovers or accepts explicit field relationships, and uses
those relationships to answer exact searches across reports. It also provides
comparison, group-membership, change-baseline, chart, deduplication,
transformation, export, scheduling, and offline evidence-based risk views.

Point does not require an Internet connection for normal import, search,
comparison, change detection, or risk analysis. Point Fetcher is a separate,
explicitly configured HTTPS download component.

## Processing flow

1. Files enter Inbox through user selection, drag-and-drop, scheduling, or the
   optional Fetcher.
2. Extension, size, structure, and supported-format checks reject invalid
   inputs. XLSX/XLSM ZIP paths are checked for traversal patterns.
3. Excel imports disable macros, events, alerts, and external-link updates and
   open a temporary copy read-only. The native reader is attempted first.
4. Each worksheet is converted independently and bounded by row, column,
   result, clipboard, and file-size limits.
5. Headers and values are normalized. Exact indexes are built only when the
   relevant lookup needs them. An unchanged refresh reuses previously
   validated relationships and lookup state.
6. Automatic relationships require compatible fields, sufficient overlap,
   and uniqueness safeguards. User-defined equivalent and list relationships
   are kept separate from ordinary synonyms.
7. Queries traverse only validated relationship edges, preserve source-row
   identity, deduplicate identical evidence, and enforce output limits.
8. Exports escape spreadsheet formulas, optionally mask highly sensitive
   fields, and can block possible payment-card numbers.
9. Security-relevant actions append a chained SHA-256 audit record.

## Protections verified in this review

- Local processing for core analysis and offline risk assessment.
- HTTPS-only Fetcher URLs, HTTP status checks, timeouts, and a 2 GiB limit.
- Secrets stored in Windows Credential Manager rather than configuration.
- Bearer/API-header newline rejection to prevent header injection.
- Downloaded-file signature and structural validation before publication.
- Atomic staging-to-Inbox activation to avoid partial-file imports.
- Safe output filenames enforced both in the UI and when configuration loads.
- Excel macro, event, alert, and external-link suppression.
- Excel fallback launches the explicit System32 PowerShell executable.
- Excel fallback execution has a bounded 15-minute timeout.
- Installed reader script must be a regular non-reparse file.
- Windows DPAPI protection for saved workspaces and policy configuration.
- Protected ACLs for Inbox, Workspace, Exports, and Logs.
- Optional Windows-group access enforcement.
- CSV formula-injection protection and sensitive-field export controls.
- Bounded parsing, results, clipboard operations, undo history, and risk text.
- Full-path System32 loading of the Rich Edit library used by Risk Analysis.
- Per-user named-event Inbox notification with a protected explicit ACL; no
  global window-message broadcast is used.
- Macro-enabled XLSM is rejected consistently at every supported input path.
- WebView2 pop-ups are blocked and certificate failures are surfaced as
  blocked navigation; browsing and download sources remain HTTPS-only.
- Executables/scripts and mutable data are separated. Mutable data is stored
  beneath `%LOCALAPPDATA%\Point`, with non-destructive legacy migration.

## Defects corrected by this review

1. PowerShell search-path hijacking: the Excel fallback previously invoked
   `powershell.exe` by name. It now resolves and launches the executable from
   the Windows System32 directory using an explicit application path.
2. Persisted filename traversal: Fetcher UI input was safe, but a manually
   modified configuration only rechecked the extension. Configuration loading
   now rejects path separators, reserved punctuation, control characters,
   trailing spaces/dots, oversized names, and non-basename values.
3. Unbounded Excel-reader wait: the fallback reader could previously block a
   refresh indefinitely. It now receives a generous but finite 15-minute
   execution window.

## Remaining limitations

- This source review and portable core test are not a penetration test,
  independent audit, or guarantee of zero vulnerabilities.
- The audit chain is tamper-evident for ordinary changes but is not digitally
  signed; an administrator with full file and application access could replace
  both the log and executable.
- Imported source reports remain as files on disk. DPAPI protects saved Point
  workspace state, not the original Excel/CSV source files.
- Field relationships prove value correspondence, not real-world identity.
  Ambiguous names must be resolved through a strong identifier or explicit
  relationship; incorrect manual mappings can produce incorrect results.
- Offline risk scores are evidence-based prioritization unless an imported
  field supplies an authoritative CVSS score. They are not a certified PCI DSS
  or NIST compliance determination.
- The Windows UI and installer must still be compiled, scanned, and tested on
  the target Windows architecture through the GitHub workflow.

## Production release checks

- Build with MSVC warnings treated as errors.
- Run the complete core regression suite.
- Scan the source and installer with an approved SAST/antimalware service.
- Code-sign and timestamp the executable and installer.
- Verify signer and SHA-256 before deployment.
- Test with non-production copies of representative large workbooks.
- Validate every manual field link with known records before broad searches.
- Restrict source-report and export folder access to authorized staff.
