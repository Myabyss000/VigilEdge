# Changelog

All notable changes to ThreatLoom will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/).

## [1.0.0] — 2026-02-07

### Added
- FastAPI backend with async SQLAlchemy (SQLite/PostgreSQL)
- Multi-format log ingestion: JSON, syslog (RFC 3164/5424), raw text
- Three-layer detection engine: signature rules, behavioral analysis, cross-log correlation
- MITRE ATT&CK mapping for 14 attack types
- Automated response engine with SOAR playbooks (block IP, rate limit, temp ban)
- Incident management with triage workflow, notes, and timeline
- Real-time SOC dashboard with Chart.js visualizations
- WebSocket real-time streaming (alerts, logs, incidents, metrics)
- JWT authentication with RBAC (Admin, SOC Analyst, Viewer)
- Audit logging for all write operations
- Hot/warm/cold/purge data retention lifecycle
- GeoIP enrichment (MaxMind GeoLite2 with stub fallback)
- 20 default detection rules (YAML)
- 9 default SOAR playbooks (YAML)
- Comprehensive test suite
- One-click launcher (`run.bat`)
