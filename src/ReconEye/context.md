# PS-011 Project Handoff

**Contents:** (1) Project statement, (2) Architecture decision, (3) Build plan.
**Status at time of writing:** Architecture decided (Architecture A). Build plan drafted. No code written yet.

---

# PART 1: PROJECT STATEMENT

**Source note:** The verbatim text of problem statement PS-011 was not available when this file was written. This part records what the architecture document states or implies about it.

## 1.1 Problem context (stated or implied)

- PS-011 is an external-asset monitoring and change-detection tool: it probes approved targets on a schedule, detects changes and misconfigurations, and raises alerts.
- The problem statement explicitly bans unrestricted scanning. Only a small set of documented checks is allowed.
- The problem statement is read as a scoring rubric (see 1.3).
- Seeded issues in the primary lab: **expired certificate**, **hostname/SAN mismatch**, **dangling DNS (CNAME)**.
- Deliverables include a **false-positive analysis**, which must be measured (precision/recall against ground truth), not anecdotal.
- Scheduled operation is claimed, so scheduling must be real and persistent.
- Alerts, a dashboard, reports, a baseline concept, and finding lifecycle states are part of the solution.
- The solution is judged and demoed live. Judges should understand the data flow in 60 seconds.

## 1.2 Working assumptions

| # | Assumption | Status |
|---|---|---|
| 0 | Small team (2-4 people), 24-48 hour build window | Stated in architecture doc |
| 1 | Primary target is a **simulated lab** (Docker Compose, CoreDNS, local DNS, seeded faults), with optionally **one real approved domain** if organisers provide one | Proceeded with, not corrected |
| 2 | The 4 documented checks are C1 TCP connect, C2 banner/protocol identification, C3 TLS handshake + certificate inspection, C4 HTTP HEAD fingerprint | Proceeded with, not corrected |
| 3 | Python is acceptable for the whole team | **Explicitly confirmed** |
| 4 | Alerts go to dashboard, JSONL log, webhook, and MailHog email | Proceeded with, not corrected |

If assumptions are wrong, the decision may shift (see 2.9).

## 1.3 What the architecture must optimise for (priority order)

1. **Provable scope enforcement.** Not "we promise", but "the code cannot connect to an unapproved target."
2. **Trustworthy change detection.** Low noise, explainable diffs, honest confidence levels.
3. **Deterministic, repeatable demo and evaluation.** Seeded issues injectable on demand; precision/recall computable against ground truth.
4. **Low live-demo risk.** Fewer moving parts.
5. **Clear explainability.** Judges understand the data flow in 60 seconds.

## 1.4 Workload sizing

20 domains + 10 hosts is roughly **500 probes per cycle** (about 200 DNS queries, 30 TLS handshakes, 100 port checks, plus discovery). This finishes in under a minute with polite rate limits. It is not a scale problem, so architectures justified by scale (queues, workers, microservices, cloud-native) are over-engineering.

## 1.5 Explicitly out of scope

Vulnerability scanning, CVE matching, HTTP crawling, unrestricted/full port scanning, full service fingerprinting (nmap-style), and probing any unapproved target.

---

# PART 2: ARCHITECTURE DECISION

## 2.1 Candidates and scoring

- **A. Async Python modular monolith:** asyncio collectors, SQLite, FastAPI with server-rendered UI, in-process scheduler, Docker Compose lab.
- **B. Python distributed pipeline:** FastAPI, Celery, Redis, PostgreSQL, React SPA ("production-looking").
- **C. Go single binary:** goroutine collectors, embedded SQLite, embedded static UI.
- **D. Tool-orchestration glue:** wrap subfinder/dnsx, nmap/masscan, tlsx/testssl, httpx; store in Elasticsearch/JSON; view in Grafana/Kibana (lighter variant: GitHub Actions cron + git diff on JSON).
- **E. Serverless/cloud-native:** EventBridge, Lambda, DynamoDB/S3, hosted dashboard.

| Criterion (1-5, higher is better) | A | B | C | D | E |
|---|---|---|---|---|---|
| Scope enforceability | 5 | 4 | 5 | 2 | 3 |
| Build speed | 5 | 2 | 3 | 4 | 2 |
| Determinism / testability | 5 | 3 | 4 | 2 | 2 |
| Demo reliability | 4 | 3 | 3 | 3 | 2 |
| Explainability to judges | 5 | 4 | 4 | 2 | 3 |
| Low ops complexity | 5 | 2 | 4 | 3 | 2 |
| Extensibility | 3 | 5 | 4 | 3 | 4 |
| **Total** | **32** | **23** | **27** | **19** | **18** |

Scores are engineering judgment, not measurements.

**Why not B:** Celery + Redis + Postgres + React SPA adds four services to debug for zero benefit at this workload. Distributed queues make "every outbound connection passes through the scope guard" harder to demonstrate because the guard must live in workers across processes.
**Why not C (Go):** Technically excellent, but Python gives faster iteration, richer X.509 handling via `cryptography`, the FastAPI/Jinja ecosystem, and pytest ergonomics. If the team is Go-native, C is a legitimate alternative and the rest of the design still applies.
**Why not D:** Nmap's capability surface is huge, so proving "only 4 documented checks" becomes command-line-flag argument-building rather than code paths. Output parsing is brittle and judges may see it as "a wrapper." The alerting/change-detection logic (the real value) is the same work either way. Nmap is still planned as an independent validation oracle in the lab during evaluation, not as the engine.
**Why not E:** Cloud lock-in, IAM setup, and cold-start debugging with no benefit for a lab demo.

## 2.2 Decision: Architecture A

```
 scope.yaml (approved, hashed) ──► ScopeGuard ◄── every outbound call + audit_log
                                       │
 Scheduler (APScheduler / CLI) ──► Orchestrator (asyncio, rate limit, semaphores)
                                       │
          ┌────────────┬───────────────┼────────────────┐
      DNS collector  TLS collector  Port/Service     Discovery (scope-declared,
      (dnspython)    (ssl + x509)   checks C1-C4     bounded labels, AXFR/CT)
          └────────────┴───────┬───────┴────────────────┘
                               ▼
                    Normalizer (canonical form)
                               ▼
      SQLite: assets · snapshots · observations · baseline · findings · audit
                               ▼
         Diff Engine (vs last run, vs baseline) ─► Rule Engine
                               ▼
     Findings (severity, confidence, evidence, remediation, lifecycle)
          ┌────────────────────┼─────────────────────┐
     Alert dispatcher       Reports            FastAPI + HTMX dashboard
     (webhook/MailHog/log)  (MD/HTML/PDF)      (inventory, diff, findings, FP, audit)

 Docker Compose lab: CoreDNS zone · nginx (valid/expired/mismatch) ·
                     extra-port service · dangling CNAME · mutator + ground_truth.yaml
```

## 2.3 Stack, layer by layer

| Layer | Choice | Why | Rejected |
|---|---|---|---|
| Language | Python 3.11+ | Fastest path; best libraries for DNS and X.509 | Go, Node |
| Concurrency | asyncio + semaphores + token-bucket limiter | Right-sized for I/O-bound probes; rate limits trivial and visible | Threads, Celery |
| DNS | dnspython (async resolver, configurable nameserver) | Full RR types; distinguishes NXDOMAIN / NODATA / SERVFAIL / timeout; can target lab CoreDNS | `socket.getaddrinfo` (loses record types and error semantics) |
| TLS | stdlib `ssl` + `cryptography` | Two-view certificate approach (2.5 #2) | Shelling out to `openssl s_client` / testssl |
| Port checks | Native `asyncio.open_connection` | Every connection is in project code, so the guard is enforceable | nmap / masscan |
| Storage | SQLite (WAL mode) via SQLAlchemy 2.0 | Zero-ops, portable evidence file, easy demo backup; dashboard reads while scanner writes | Postgres (extra service), JSON/git (poor querying) |
| Data model | Relational identity + normalized JSON attributes per observation | Stable asset IDs make diffing easy; JSON avoids a dozen tables | Fully normalized schema |
| Scheduler | APScheduler in-process + run-once CLI | Demo at 60s intervals, production at 6h, cron-compatible | Celery beat, Airflow |
| API/UI | FastAPI + Jinja2 + HTMX (+ Chart.js) | One language, one process, live-updating dashboard with no JS build chain | React SPA |
| Alerts | Dashboard + JSONL log + webhook (Slack/Discord) + SMTP to MailHog | Visible, demo-friendly, no external accounts | Real email provider |
| Lab | Docker Compose on a private bridge network; scanner runs as a container inside it | Deterministic, safe, legal; avoids Docker Desktop host-networking limits on Windows/macOS (static bridge IPs not reachable from host) | Real cloud assets |
| Tests | pytest with golden diff fixtures + evaluation harness | Directly produces the false-positive analysis deliverable | Manual testing |

## 2.4 The four documented checks (plus DNS)

| Check | Action | Detects |
|---|---|---|
| **DNS** (collector, not a numbered check) | Query A/AAAA/CNAME/MX/NS etc. via dnspython against the configured nameserver | Record changes; dangling CNAME candidates |
| **C1** TCP connect | Open a socket to host:port, confirm it accepts, close | Port open/closed; new or removed port |
| **C2** Banner / protocol identification | After connect, read the first bytes and identify the service (SSH, HTTP, SMTP, ...) | Unexpected service on an approved port; banner change |
| **C3** TLS handshake + certificate inspection | Handshake, extract and parse the certificate (expiry, issuer, SANs, serial, fingerprint, key type) | Expired, hostname/SAN mismatch, self-signed, certificate changed (fingerprint vs baseline), upcoming expiry |
| **C4** HTTP HEAD fingerprint | Send HEAD, inspect status code and headers (Server, X-Powered-By, etc.) | Server/version header change, header removal, status change |

**Applicability (from scope design):** Domains get DNS plus TLS (C3) on 443 and nothing more. Hosts get C1-C4 only on their listed ports. All collectors are limited to these checks; any new check must be documented and approved first.

## 2.5 Design decisions that carry the project

**1. Scope guard as a single choke point.**
All network I/O goes through one `NetClient` that calls `guard.authorize(target, port, check_id)` and writes an `audit_log` row (allowed or denied). Collectors never import `socket` directly, and a unit test enforces that. Additional safeguards:
- Resolve once, pin the IP, connect to the IP with SNI set separately (prevents DNS-rebinding / TOCTOU scope escapes).
- Port checks run only on approved hosts and only on their listed ports.
- The scope file is canonicalized and SHA-256 hashed; the hash is stored with every snapshot. Optionally signed (ed25519) so a tampered scope file makes the tool refuse to start.
- Demo moment: "scan google.com" returns DENIED.

**2. TLS needs two views of the same certificate.**
With verification disabled (needed to inspect expired or self-signed certs), `getpeercert()` returns an empty dict. So the collector:
1. grabs the leaf in DER form and parses it with `cryptography` (notBefore/notAfter, issuer, SANs, serial, fingerprint, key type);
2. performs a separate verified handshake to capture why verification failed ("certificate has expired", "self-signed", "hostname mismatch").
This yields categorized, evidence-backed findings.

**3. Dangling DNS is a scored candidate, never a verdict.**
The pipeline resolves the CNAME chain (depth cap, loop detection) and classifies the terminal state:
- NXDOMAIN on the target: medium-high confidence.
- NODATA: lower confidence.
- SERVFAIL or timeout: "unknown"; retry, never a finding on its own.
- Provider-pattern match (`*.azurewebsites.net`, `*.s3.amazonaws.com`, etc.) raises confidence.
Findings are worded "candidate, requires manual verification, no takeover attempted." Default is DNS-only evidence. HTTP fingerprinting is opt-in and limited to lab hosts, because connecting to a name that resolves to a third party's infrastructure is itself a scope question.

**4. Baseline lifecycle.**
The first run produces a *proposed* baseline that a human approves. Diffing works two ways: **delta vs previous run** (triggers alerts) and **drift vs baseline** (stays open as a finding until resolved or accepted). Finding states: new, open, resolved, acknowledged, accepted-risk, false-positive.

**5. Noise handling (the quality differentiator).**
- Normalization lowercases names, sorts RRsets, ignores TTL, and treats CDN-pool IP rotation as benign while IPs stay within known ranges.
- Certificate renewal (same SANs and issuer, new serial, later expiry) is an info event, not an alert.
- Confirmation rescan: re-probe once before alerting on appear/disappear, to filter transient timeouts.
- Findings are deduplicated by fingerprint.
- Expiry alerts fire once per threshold crossing (30/14/7/0 days).

**6. The lab includes decoys, not just seeded faults.**
Alongside the three seeded issues, the mutator injects benign changes: cert renewal, TTL change, record reordering, IP rotation. The evaluation harness runs many cycles and computes TP/FP/FN, precision, and recall per issue type, and compares **naive diffing** against **normalized diffing + confirmation rescan**, producing a measured before/after result.

## 2.6 Findings and alerting

- **Finding fields:** severity, confidence, evidence, remediation, lifecycle state, fingerprint (dedup).
- **Dashboard pages:** inventory, diff view, finding detail (with lifecycle/false-positive actions), audit log.
- **Alert channels (all optional except the dashboard, which is the fallback):**
  - Dashboard: findings stored in SQLite and rendered via FastAPI/HTMX.
  - JSONL log: append-only, machine-readable record of every finding fired (also usable for post-run analysis).
  - Webhook: Slack/Discord/HTTP, configurable by severity.
  - SMTP to MailHog (captured at its web UI), with a digest mode (one email per cycle).
- Channels are independent: failure of one (e.g., Slack down) must not prevent the others.
- **Reports:** Markdown/HTML (PDF is nice-to-have).

## 2.7 Lab design

- Docker Compose on a private bridge network (172.20.0.0/24). Scanner runs inside it.
- Containers: CoreDNS (authoritative `lab.internal`), three nginx vhosts (valid / expired / SAN-mismatch), an extra-port service (22/8080/8443), MailHog, mutator, scanner. Details in 3.4.
- Seeded faults: expired cert, SAN mismatch, dangling CNAME (to a provider-pattern name that lab CoreDNS answers NXDOMAIN for; the scanner queries only lab DNS, so nothing leaves the lab).
- Certificates are generated with Python `cryptography` (expired = `not_valid_after` in the past), not `openssl -days`. A `--now` clock override makes expiry tests deterministic.
- `ground_truth.yaml` lists, per cycle, which changes are real issues and which are decoys.
- **Optional real domain:** added to `scope.yaml` as just another asset; DNS + TLS(443) only; no HTTP crawling or discovery; no port-scanning of third-party IPs resolved from it; scanned only with explicit approval.
- Nmap may be used in the lab as an independent cross-validation oracle during evaluation.

## 2.8 Pros, cons, and mitigations

**Pros:** fastest path to a working end-to-end demo and small enough for the whole team to understand; scope enforcement is structural and testable; deterministic lab + ground truth gives a real precision/recall table; one `docker compose up` with minimal demo failure surface; clean interfaces (collector, rule, alert sink) make extension cheap.

| Weakness | Reality check | Mitigation |
|---|---|---|
| Not horizontally scalable | Irrelevant at 20 domains / 10 hosts | Documented upgrade path: split orchestrator and workers behind a queue; swap SQLite for Postgres via SQLAlchemy DSN |
| SQLite is single-writer | Only one scanner writes | WAL mode; writes happen after collection in one transaction |
| In-process scheduler dies with the process | Real concern for "scheduled" claims | Persist last/next run in DB, handle misfires on startup, offer run-once CLI for cron/systemd |
| HTMX UI less flashy than React | Judges care about clarity | Spend saved time on diff view and finding detail pages |
| Native service identification shallower than nmap | PS asks for 4 documented checks, not full fingerprinting | Define checks precisely; cross-validate against nmap in the lab |
| Simulated lab under-exercises real-world noise (CDNs, flaky resolvers) | Fair criticism | Decoy mutations; optionally one real approved domain |
| Async pitfalls (a blocking call stalls everything) | Real but manageable | Keep CPU work (cert parsing) tiny; timeouts everywhere; a test that fails on blocking calls |

## 2.9 Top risks and the condition that would change the decision

- **Scope creep:** adding vulnerability scanning, CVE matching, or HTTP crawling (banned by the PS).
- **Cert time-travel testing:** generate certs with `cryptography`; need `--now` override.
- **Docker networking:** static bridge IPs are not reachable from the host on macOS/Windows, hence the scanner runs inside the compose network.
- **Weak FP analysis:** without decoys and repeated cycles it becomes anecdotes; the harness is a first-class deliverable.
- **Decision change condition:** a frontend-heavy team wanting a polished SPA. In that case keep the same backend and swap HTMX for React with a thin JSON API. A Go-native team could choose Architecture C with the same design.
- **Assumption-dependent shifts:** no local lab allowed (determinism and precision/recall become anecdotal); larger scope (add lab containers or VMs on the Docker network); no stored baseline (diff becomes "changes in the last X minutes").

---

# PART 3: BUILD PLAN

**Planning basis:** 3-4 people, 48-hour window, simulated lab, Python 3.11+. Each phase ends at a demoable checkpoint.

## 3.1 Team split (4 people; merge roles if fewer)

| Role | Owns | Merge note |
|---|---|---|
| **A: Core** | ScopeGuard, NetClient, audit log, orchestrator, scheduler, CLI | Critical path; keep solo |
| **B: Collectors** | DNS, TLS (C3), port checks (C1/C2), HTTP HEAD (C4), normalizer | |
| **C: Lab + Eval** | Docker Compose lab, mutator, ground truth, evaluation harness, pytest fixtures | Merge with D if team is 3 |
| **D: Findings + UI** | Diff engine, rule engine, lifecycle, FastAPI/HTMX dashboard, alerts, reports | Merge with C if team is 3 |

With 2 people: A+B and C+D.

## 3.2 Repo structure

```
ps011/
├── scope/scope.yaml            # approved targets (hashed, optionally signed)
├── src/scanner/
│   ├── core/       scope_guard.py  net_client.py  audit.py  config.py
│   ├── collectors/ dns.py  tls.py  ports.py  http_head.py  discovery.py
│   ├── pipeline/   orchestrator.py  normalizer.py  scheduler.py
│   ├── analysis/   diff.py  rules.py  findings.py  baseline.py
│   ├── alerts/     dispatcher.py  webhook.py  smtp.py  jsonl.py
│   ├── db/         models.py  session.py
│   ├── web/        app.py  templates/  static/
│   └── cli.py
├── lab/
│   ├── docker-compose.yml  coredns/  nginx/  extra-port/
│   ├── mutator/    mutator.py  mutation_schedule.yaml
│   └── ground_truth.yaml
├── eval/           harness.py  metrics.py  report_template.md
└── tests/          unit/  golden/  integration/
```

## 3.3 Contracts (agreed in hours 0-2)

**scope.yaml (illustrative format)**
```yaml
version: 1
approved_by: "Organisers / Team"
domains:
  - name: valid.lab.internal
    checks: [DNS, C3]
  - name: expired.lab.internal
    checks: [DNS, C3]
  - name: mismatch.lab.internal
    checks: [DNS, C3]
  - name: dangling.lab.internal
    checks: [DNS]
hosts:
  - ip: 172.20.0.20
    ports: [22, 8080, 8443]
    checks: [C1, C2, C3, C4]
discovery:
  allowed_labels: [www, api, mail, dev]
  max_candidates: 50
limits:
  max_rps: 20
  per_host_concurrency: 2
  timeout_s: 5
```

**Database tables (SQLAlchemy 2.0)**

| Table | Key columns |
|---|---|
| `assets` | id, kind (domain/host/service), identifier, first_seen |
| `snapshots` | id, started_at, finished_at, scope_hash, status |
| `observations` | id, snapshot_id, asset_id, check_id, attrs_json, error_class |
| `baseline` | id, snapshot_id, approved_by, approved_at |
| `findings` | id, fingerprint (unique), asset_id, rule_id, severity, confidence, evidence_json, state, first_seen, last_seen |
| `audit_log` | id, ts, target, port, check_id, decision (allow/deny), reason, scope_hash |
| `scheduler_state` | last_run, next_run |

**Interfaces**
- `Collector.collect(target) -> list[Observation]`
- `Rule.evaluate(diff, baseline) -> list[Finding]`
- `AlertSink.send(finding)`

## 3.4 Lab containers

| Container | IP | Purpose |
|---|---|---|
| coredns | 172.20.0.2 | Authoritative zone `lab.internal` |
| nginx-valid | .10 | Valid cert (private CA); the control |
| nginx-expired | .11 | **Seeded fault 1:** expired cert |
| nginx-mismatch | .12 | **Seeded fault 2:** SAN does not match hostname |
| extra-port | .20 | Open ports 22/8080/8443 (banner and HEAD tests) |
| (DNS only) | n/a | **Seeded fault 3:** dangling CNAME to a provider-pattern name that lab CoreDNS answers NXDOMAIN for |
| mailhog | .30 | SMTP capture |
| mutator | .40 | Applies seeded and decoy changes on a schedule |
| scanner | .50 | Runs inside the network |

**Decoys (benign, must not alert):** cert renewal (same SANs/issuer, new serial), TTL change, RRset reordering, IP rotation within a known range, one transient timeout.

## 3.5 Phased timeline

**Phase 0: Kickoff (hrs 0-2)**
- Create repo, CI skeleton, lint/pytest setup.
- Agree on scope.yaml format, DB schema, interfaces.
- *Checkpoint:* everyone can `pip install -e .` and run `pytest` (even with one trivial test).

**Phase 1: Foundations (hrs 2-10)**
- A: ScopeGuard (canonicalize + SHA-256 hash scope, `authorize()`), NetClient wrapper, audit_log writes, resolve-once IP pinning. Unit test: unapproved target is DENIED.
- B: DNS collector against lab CoreDNS; distinguish NXDOMAIN/NODATA/SERVFAIL/timeout.
- C: Compose lab up with CoreDNS and three nginx vhosts; generate certs with Python `cryptography`.
- D: DB models, migrations, session setup, JSONL sink, skeleton FastAPI app.
- *Checkpoint 1:* `scan google.com` is DENIED and logged; DNS results for the lab are stored in SQLite.

**Phase 2: Collectors (hrs 10-20)**
- B: TLS dual-view collector (C3), port checks (C1/C2), HTTP HEAD (C4), bounded discovery, normalizer (lowercase, sort RRsets, ignore TTL).
- A: Orchestrator with semaphores and token-bucket rate limiting; one snapshot per run in a single transaction; run-once CLI.
- C: Extra-port service and dangling CNAME record; golden observation fixtures.
- D: Diff engine against the previous run.
- *Checkpoint 2:* one command runs a full cycle and stores a snapshot containing all three seeded faults as raw observations.

**Phase 3: Findings (hrs 20-30)**
- D: Rule engine (expired cert, hostname mismatch, self-signed, upcoming expiry at 30/14/7/0 days, new/removed port, service banner change, dangling CNAME candidate with confidence tiers). Fingerprint dedup and lifecycle states. Baseline propose/approve flow.
- A: Confirmation rescan (re-probe once before alerting on appear/disappear); scheduler with persisted next_run and misfire handling on startup.
- B: Unit tests for every collector error path (timeouts, refused, bad TLS).
- *Checkpoint 3:* the three seeded faults produce findings with correct severity, confidence, and evidence; decoys produce no alerts.

**Phase 4: Surface (hrs 30-38)**
- D: Dashboard pages (inventory, diff view, finding detail with lifecycle buttons, audit log). Alert dispatcher (dashboard, JSONL, webhook, SMTP to MailHog). Digest mode.
- A: Scope-file hash on every snapshot; optional ed25519 signature check at startup.
- C: Mutator with a schedule (seeded and decoy changes); begin the evaluation harness.
- B: Markdown/HTML report export.
- *Checkpoint 4:* end-to-end demo works: mutator changes something, scanner detects it, alert lands on dashboard, in the log, and in MailHog.

**Phase 5: Evaluation (hrs 38-44)**
- C: Harness runs N cycles (target 30+), scores alerts against ground_truth, outputs TP/FP/FN, precision, recall per issue type.
- C + D: Run naive diff vs normalized diff + confirmation rescan; produce the before/after table (the false-positive analysis deliverable).
- A + B: Fix what the harness exposes (usually normalization gaps).
- *Checkpoint 5:* a results table and plot ready for slides.

**Phase 6: Hardening and demo (hrs 44-48)**
- Feature freeze at hour 44; only bug fixes after.
- Test a clean `docker compose up` on a fresh machine and on the demo laptop's OS.
- Rehearse the demo twice; record a fallback video.
- README: architecture diagram, scope proof, the four checks, how to run, limitations.

**Syncs:** 10-minute team syncs at hours 10, 20, 30, 38.

## 3.6 Test strategy

- **Scope guard:** unit tests for allowed, denied, and unlisted-port cases; a test that fails if any collector imports `socket` directly.
- **Golden diffs:** fixed before/after observation pairs with expected findings; decoy pairs must yield zero findings.
- **Clock override:** `--now` flag for deterministic expiry tests.
- **Async hygiene:** a test that fails on blocking calls in the event loop.
- **Integration:** compose up, run one cycle, assert the exact finding set.

## 3.7 Cut line (if behind schedule)

- **Must have:** ScopeGuard with audit log, DNS and TLS collectors, diff + rules for the 3 seeded faults, dashboard findings page, JSONL log, evaluation table.
- **Should have:** C1/C2/C4 checks, baseline approval, MailHog email, lifecycle buttons, confirmation rescan.
- **Nice to have (cut first):** webhook, ed25519 signing, PDF report, discovery module, real approved domain.

## 3.8 Demo script (about 5 minutes)

1. `docker compose up`; show the architecture on one slide (60 s).
2. Attempt to scan an unapproved target: DENIED, with the audit log row.
3. Run a cycle: three findings appear on the dashboard with evidence and confidence.
4. Trigger the mutator: a decoy (cert renewal) yields an info event only; a real change yields a new alert in MailHog.
5. Show the evaluation table: naive vs normalized false-positive counts.
6. Close on scope enforcement: the hashed scope file and the choke-point code.

## 3.9 Schedule risks

| Risk | Early warning | Response |
|---|---|---|
| Docker networking surprises | Scanner cannot reach lab at hour 6 | Scanner stays inside the compose network (already the plan) |
| TLS edge cases (empty `getpeercert()`) | Parsing fails on expired cert | DER + `cryptography` path from day one |
| Normalization gaps cause noisy FPs | Harness shows FP > 0 on decoys | Fix in the normalizer, not by loosening rules |
| UI time sink | Dashboard still unstyled at hour 34 | Plain HTMX tables; focus effort on the diff view |
| Integration drift | Interfaces change mid-build | Syncs at hours 10, 20, 30, 38 |
