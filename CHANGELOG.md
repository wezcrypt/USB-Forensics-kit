# Changelog

All notable changes to WezCrypt USB Forensics Kit are documented here.
The format follows [Keep a Changelog](https://keepachangelog.com/) and the project uses [Semantic Versioning](https://semver.org/).

## [1.0.0] - 2026-10-09

### Added
- Portable ONEDIR build (`build.bat`) producing `WezCryptUFK.exe` (GUI) and `WezCryptUFK-cli.exe` (CLI) that run from USB without installation.
- 25 collection modules: Event Logs (wevtutil export + parsing), Prefetch (v17/23/26/30, MAM via ntdll), Amcache (esentutl /vss),
  Shimcache, UserAssist, ShellBags, Jump Lists (OLE + DestList), LNK files, RecentDocs/RunMRU/TypedPaths, USB device history
  (USBSTOR/USB/MountedDevices/MountPoints2/setupapi), registry hive export, scheduled tasks, services, startup locations,
  installed applications, running processes, network state, file-system triage, Recycle Bin, and Chrome/Edge/Brave/Opera/Firefox.
- Offline REGF hive parser, OLE compound file reader, LNK/shell item, Prefetch, Recycle Bin, PE and task XML parsers.
- Evidence integrity: hash-while-copy acquisition with post-copy verification, SHA-256 manifest with self-hash,
  hash-chained chain-of-custody log, UTC timestamps, session UUIDs, error and live-action logs.
- Analysis engine with 15 evidence-backed rule groups (including 15 suspicious command-line patterns), unified timeline (k-way merge), observables extraction, IOC matching,
  executive summary and recommendations.
- Reports: searchable/filterable offline HTML (main + per-browser), PDF (Unicode/Arabic shaping), JSON and CSV (Excel-friendly UTF-8).
- Tkinter GUI with Dashboard, Evidence Collection, Live Progress, Evidence Explorer, Timeline Analysis, Hash Verification,
  Report Generator, Settings and About pages.
- 58 automated pytest tests using synthetic artifacts only.
