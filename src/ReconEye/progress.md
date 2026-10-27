# PS-011 Build Progress

**Last Updated:** 2026-10-01T15:00:00Z
**Current Phase:** Phase 2: Database & Collectors
**Overall Status:** ~25% complete across all phases

## Phase Checklist
- [x] Phase 0: Setup
- [ ] Phase 1: Scope Guard & Foundations
- [ ] Phase 2: Database & Collectors
- [ ] Phase 3: Findings & Rules
- [ ] Phase 4: Surface (Dashboard & Alerts)
- [ ] Phase 5: Evaluation Harness
- [ ] Phase 6: Hardening & Demo

---

## Component Status Table

| Component | Phase | Status | Tests | Blockers | Key Details |
|-----------|-------|--------|-------|----------|-------------|
| Project Setup | 0 | ✅ DONE | 5/5 pass | None | pyproject.toml, pytest.ini, repo structure created |
| ScopeGuard | 1 | ✅ DONE | 4/4 pass | None | authorize(), SHA-256 hash, audit_log, canonicalize, resolve_once |
| NetClient | 1 | ✅ DONE | 1/1 pass | None | Wraps asyncio.open_connection, calls ScopeGuard.authorize() |
| AuditLogSink | 1 | ✅ DONE | 1/1 pass | None | JSONL writer to ps011/data/audit.jsonl |
| CLI (scan command) | 1 | ✅ DONE | 2/2 pass | None | scan --target --port, exits 1 on deny, 0 on allow |
| DNS Collector | 2 | ⬜ TODO | 0/? | None | Depends on NetClient; uses dnspython async resolver |
| TLS Collector (C3) | 2 | ⬜ TODO | 0/? | None | Dual-view cert parsing (DER + verified handshake) |
| Port Checks (C1/C2) | 2 | ⬜ TODO | 0/? | None | Native asyncio.open_connection via NetClient |
| HTTP HEAD (C4) | 2 | ⬜ TODO | 0/? | None | HEAD request via NetClient |
| Normalizer | 2 | ⬜ TODO | 0/? | None | Lowercase, sort RRsets, ignore TTL |
| Database Models | 2 | ⬜ TODO | 0/? | None | SQLAlchemy 2.0: Asset, Snapshot, Observation, Finding, Baseline, AuditLog |
| Diff Engine | 3 | ⬜ TODO | 0/? | None | Delta vs previous run + drift vs baseline |
| Rule Engine | 3 | ⬜ TODO | 0/? | None | Expired cert, SAN mismatch, dangling CNAME, etc. |
| Baseline Lifecycle | 3 | ⬜ TODO | 0/? | None | Propose → approve → diff against |
| Alert Dispatcher | 4 | ⬜ TODO | 0/? | None | Dashboard, JSONL, webhook, SMTP (MailHog) |
| FastAPI/HTMX Dashboard | 4 | ⬜ TODO | 0/? | None | Inventory, diff view, finding detail, audit log |
| Evaluation Harness | 5 | ⬜ TODO | 0/? | None | TP/FP/FN, precision/recall per issue type |
| Mutator (Lab) | 5 | ⬜ TODO | 0/? | None | Seeded + decoy mutations on schedule |
| Docker Compose Lab | 5 | ⬜ TODO | 0/? | None | CoreDNS, nginx vhosts, extra-port, MailHog, mutator, scanner |

---

## Phase 0: Project Setup ✅ COMPLETE
**Checkpoint:** Everyone can `pip install -e .` and run `pytest`

### Completed:
- [x] pyproject.toml with all dependencies
- [x] pytest.ini with asyncio_mode=auto
- [x] Project folder structure (ps011/collectors, ps011/models, ps011/tests)
- [x] scope.py: ScopeGuard with authorize(), SHA-256 hash, audit_log
- [x] net.py: NetClient wrapper with ConnectionDenied exception
- [x] collectors/base.py: Abstract Collector, Rule, AlertSink
- [x] models/observation.py: Observation, Finding dataclasses
- [x] config.py: Scope YAML loader with Pydantic models
- [x] tests/conftest.py: Fixtures for scope.yaml
- [x] tests/test_scope.py: 5 unit tests (all passing)
- [x] README.md with install/run instructions

### Test Summary:
- test_approved_domain_and_port_authorized ✅ PASS
- test_unapproved_domain_denied ✅ PASS
- test_unapproved_port_on_approved_domain_denied ✅ PASS
- test_scope_hash_is_deterministic ✅ PASS
- test_net_client_denies_unapproved ✅ PASS (async)

### Notes:
- All imports are stdlib or in pyproject.toml
- No direct socket imports in any module (verified)
- Scope hash is SHA-256, deterministic across runs
- CLI entry point `python -m ps011.scope scope.yaml` prints hash
- NetClient is the single choke-point for outbound connections

---

## Phase 1: Scope Guard & Foundations ✅ COMPLETE
**Checkpoint:** `scan google.com` is DENIED and logged; audit_log captures every attempt; JSONL audit log persisted

### Completed:
- [x] Implement ScopeGuard.authorize() with audit log writes
- [x] Implement ScopeGuard.canonicalize_target() and resolve_once()
- [x] Implement NetClient wrapper with scope enforcement choke-point
- [x] Implement AuditLogSink (JSONL writer to ps011/data/audit.jsonl)
- [x] Implement CLI scan command (--target, --port, --scope)
- [x] Unit test: approved target connects (NetClient + mock)
- [x] Unit test: unapproved target denied + logged
- [x] Unit test: audit log format valid JSONL with ISO8601 timestamps
- [x] Unit test: CLI denied exits 1, audit log written
- [x] Unit test: CLI allowed exits 0, audit log written

### Blockers:
- None

### Notes:
- Audit log entries: {ts, target, port, check_id, decision, reason, scope_hash}
- ScopeGuard checks both domain-level (standard ports 80/443/53) and host-level (explicit ports)
- Each ScopeGuard instance has independent audit_log for testing
- CLI persists ScopeGuard.audit_log to JSONL file after each scan
- No direct socket imports in any module (verified)

---

## Phase 2: Database & Collectors ⬜ TODO
**Checkpoint:** One full scan stores observations in SQLite

### TODO:
- [ ] SQLAlchemy models: Asset, Snapshot, Observation, Baseline, Finding, AuditLog, SchedulerState
- [ ] Database init, migrations
- [ ] DNS collector (C2): against lab CoreDNS, distinguish error types
- [ ] Normalizer: lowercase, sort RRsets, ignore TTL
- [ ] Integration test: one scan cycle produces snapshot with observations

### Blockers:
- None (ready to begin)

---

## Phase 3: Findings & Rules ⬜ TODO
**Checkpoint:** Three seeded faults produce findings with correct severity/confidence

### TODO:
- [ ] Rule engine (expired cert, hostname mismatch, self-signed, upcoming expiry at 30/14/7/0 days, new/removed port, service banner change, dangling CNAME candidate)
- [ ] Fingerprint dedup and lifecycle states (new, open, resolved, acknowledged, accepted-risk, false-positive)
- [ ] Baseline propose/approve flow
- [ ] Confirmation rescan (re-probe once before alerting on appear/disappear)
- [ ] Scheduler with persisted next_run and misfire handling
- [ ] Unit tests for every collector error path

### Blockers:
- Awaiting Phase 2 completion

---

## Phase 4: Surface (Dashboard & Alerts) ⬜ TODO
**Checkpoint:** End-to-end demo works; mutator changes detected, alert lands on dashboard, log, MailHog

### TODO:
- [ ] Dashboard pages (inventory, diff view, finding detail with lifecycle buttons, audit log)
- [ ] Alert dispatcher (dashboard, JSONL, webhook, SMTP to MailHog)
- [ ] Digest mode for email
- [ ] Scope-file hash on every snapshot; optional ed25519 signature check at startup
- [ ] Markdown/HTML report export

### Blockers:
- Awaiting Phase 3 completion

---

## Phase 5: Evaluation Harness ⬜ TODO
**Checkpoint:** Results table and plot ready for slides

### TODO:
- [ ] Mutator with schedule (seeded and decoy changes)
- [ ] Harness runs N cycles (target 30+), scores alerts against ground_truth
- [ ] Output TP/FP/FN, precision, recall per issue type
- [ ] Run naive diff vs normalized diff + confirmation rescan
- [ ] Produce before/after false-positive analysis table

### Blockers:
- Awaiting Phase 4 completion

---

## Phase 6: Hardening & Demo ⬜ TODO
**Checkpoint:** Clean docker compose up on fresh machine; rehearsed demo

### TODO:
- [ ] Feature freeze at hour 44
- [ ] Test clean `docker compose up` on fresh machine
- [ ] Rehearse demo twice; record fallback video
- [ ] README: architecture diagram, scope proof, four checks, how to run, limitations

### Blockers:
- Awaiting Phase 5 completion

---

## Test Coverage Summary

| Phase | Unit Tests | Integration Tests | Status |
|-------|------------|------------------|--------|
| 0 | 5/5 ✅ | — | COMPLETE |
| 1 | 8/8 ✅ | — | COMPLETE |
| 2 | 0/5 ⬜ | 0/2 ⬜ | TODO |
| 3 | 0/8 ⬜ | 0/3 ⬜ | TODO |
| 4 | 0/6 ⬜ | 0/2 ⬜ | TODO |
| 5 | — | 0/1 ⬜ | TODO |
| 6 | — | 0/1 ⬜ | TODO |

---

## Known Issues & Workarounds

| Issue | Status | Notes |
|-------|--------|-------|
| Docker networking on Windows | Pending | Scanner will run inside compose network (already planned) |
| TLS edge cases (empty getpeercert()) | Pending | DER + cryptography path from day one |
| Normalization gaps cause noisy FPs | Pending | Fix in normalizer, not by loosening rules |

---

## Build Timeline

| Milestone | Target Time | Status |
|-----------|------------|--------|
| Phase 0 kickoff | 0-2h | ✅ COMPLETE |
| Phase 1 checkpoint | 2-10h | ✅ COMPLETE |
| Phase 2 checkpoint | 10-20h | ⬜ TODO |
| Phase 3 checkpoint | 20-30h | ⬜ TODO |
| Phase 4 checkpoint | 30-38h | ⬜ TODO |
| Phase 5 checkpoint | 38-44h | ⬜ TODO |
| Phase 6 checkpoint | 44-48h | ⬜ TODO |
| Feature freeze | 44h | ⬜ TODO |

---

## Dependencies & Import Audit

**External Packages Used:**
- dnspython: DNS queries
- cryptography: X.509 certificate parsing
- fastapi: Web API
- sqlalchemy: ORM
- apscheduler: Task scheduling
- pydantic: Config validation
- pytest: Testing

**Standard Library Only (restricted):**
- ps011/scope.py, ps011/net.py: NO socket, NO urllib (scope guard enforcement)

---

## Recent Changes

### [2026-10-01T15:00:00Z] Phase 1.1 Complete (ScopeGuard, NetClient, AuditLogSink, CLI)
- Implemented ScopeGuard.authorize() with full audit logging (dict format with ISO8601 timestamps)
- Added canonicalize_target() and resolve_once() with DNS caching
- Implemented NetClient as single choke-point for all outbound connections
- Created AuditLogSink for JSONL persistence to ps011/data/audit.jsonl
- Built CLI with `scan --target --port --scope` command
- Wrote 8 unit tests (7 new + 1 existing) - all 13 tests passing
- Verified `python -m ps011.cli scan --target google.com --port 443` → DENIED, exit 1, audit log written
- Verified CLI with mock → ALLOWED, exit 0, audit log written
- Verified audit.jsonl contains valid JSON lines with scope_hash
- No direct socket imports anywhere (scope guard is the choke-point)

### [2026-10-01T14:30:00Z] Phase 0 & 1 Complete
- Created full project structure with pyproject.toml, pytest.ini
- Implemented ScopeGuard with SHA-256 scope hash, authorize() method, and audit_log
- Implemented NetClient wrapper as choke-point for outbound connections
- Added abstract Collector, Rule, AlertSink base classes
- Created Observation and Finding dataclasses
- Built config.py with Pydantic ScopeConfig models
- Wrote 5 unit tests (4 sync + 1 async) - all passing
- Verified `pip install -e .` and `python -m ps011.scope scope.yaml` work
- Verified no direct socket imports in collector modules
- Created progress.md tracking document