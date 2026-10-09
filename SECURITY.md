# Security Policy

## Supported versions

| Version | Supported |
|---------|-----------|
| 1.0.x   | Yes       |

## Reporting a vulnerability

Please report vulnerabilities privately through **https://wezcrypt.com** (contact page) rather than opening a public issue.
Include:

- affected version (`WezCryptUFK-cli --version`) and Windows build,
- a description of the issue and its impact (e.g. evidence alteration, integrity bypass, code execution via a crafted artifact),
- reproduction steps and, where possible, a **synthetic** sample artifact. Never send real case data or personal data.

We aim to acknowledge reports within 5 business days and to publish a fix and advisory once a patch is available.

## Scope notes

The kit parses untrusted on-disk structures (registry hives, LNK, Prefetch, OLE, SQLite, XML). Parsing bugs that could
crash a module are isolated per module, but anything that could alter evidence, forge integrity results, or execute code is
treated as a security issue.

## Design guarantees (by design, not configuration)

- No password, cookie value, session token, autofill or credential store is read or extracted; SAM/SECURITY hives are never exported.
- No privilege escalation, UAC bypass or access-control circumvention. Elevation only through Windows' own UAC prompt.
- Sources are opened read-only; evidence is copied, hashed while read, and re-verified after writing.
- Every operation that can affect the live system is recorded in `logs/live_actions.json` and the report.
