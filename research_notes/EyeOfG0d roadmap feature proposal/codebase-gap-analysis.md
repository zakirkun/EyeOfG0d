# EyeOfG0d — Codebase Capability Map & Gap Analysis

**Baseline:** git `5ce5386` (2026-11-19), clean working tree. Every claim below was read directly from source; where a capability is *absent*, the absence was confirmed by a repo-wide search and the search pattern is stated so it can be re-run.

**Companion docs in this folder:** `competitive-landscape.md`, `buyer-pain-points.md`, `agent-techniques.md`, `regulatory-drivers.md`. This file does not restate market claims — it only maps them onto code that exists or does not exist.

---

## 1. What the system actually is

A single Go binary (`cmd/eyeofg0d/main.go:52-54`: `-addr`, `-data`, `-proxy`) serving a JSON API plus an optionally embedded static Next.js SPA (`server/webui_embed.go:18`, build tag `embedui`), backed by **two** stores:

- **PostgreSQL** is the system of record. `db/schema.sql` is an idempotent base that is re-executed on every startup (`db/db.go:33`, `db/db.go:63`, `db/db.go:213`).
- **SQLite** (`modernc.org/sqlite`, `traffic/traffic.go:39`) is a sidecar **only** for the traffic index (`traffic/traffic.go:251`, FTS5 schema at `:125`).

There is no worker process, no queue broker, no Redis. All concurrency is goroutines inside the one process (`server/engine.go:921` planner loop, `:1121` worker loop).

This shape is the single most important constraint on feature selection: it rules out anything that needs a second deployable, a background job runner, or server-side rendering.

---

## 2. Capability inventory

Legend: **Real** = implemented and load-bearing; **Real, narrow** = implemented but scoped to a subset of the product; **Absent** = confirmed not present.

| # | Capability | Evidence | Status |
|---|---|---|---|
| 1 | Planner round → intent batch | `agent/planner.go:469` `Plan`; prompt template `:410`; `add_intent` `:448`; completion via `prove_goal` `:427` | Real |
| 2 | Worker execution + settlement | `agent/worker.go:426` `execute`; intent injected into system prompt `:476`; auto-scope write `:393`; turn cap `:535`; settlement `:503` | Real |
| 3 | Task orchestration / dispatch | `server/engine.go:921` `plannerLoop`, `:1121` `workerLoop`, `:1196` `runIntent`, `:1486` `claimNext`; steering `:549`; kill `:694` | Real |
| 4 | Human-interface agent | `agent/mainagent.go:114` `Chat` — tools `add_hint`, `add_intent`, `set_goals`, `steer_work`, `set_constraints` | Real |
| 5 | Hierarchical budgets (task→intent→round) | `agent/budget.go:107` ledger, `:192` intent meter, `:230` wrap-up blocks, `:235`/`:237` budget prompts; **env-only config** `:86-93` | Real, but not runtime-configurable |
| 6 | Coverage ledger | `db/coverage_ledger.go:161` `RecordCoverage`; append-only history `:176`; upsert `:180`; `FOR UPDATE` serialization; cap `MaxCoverageRowsPerTask=2000` `:53` | Real |
| 7 | Risk-class folding | `db/coverage_ledger.go:114` `normRiskArea` → `knowledge.Class()` canonical tokens (`knowledge/knowledge.go:607`) | Real |
| 8 | Coverage completeness semantics | `db/coverage_ledger.go:338` `CoverageCompletenessFor` → `complete/in_progress/paused/timeout/budget/aborted`; explicit caveat `:353`/`:355` ("absence of a finding does not mean the target is clean") | Real |
| 9 | Coverage agent tool | `agent/coverage_ledger.go:17` `record_coverage`, prompt block `:58` | Real |
| 10 | Finding verification (POE gate) | `db/finding_verification.go:30` `SetFindingVerification`; enforcement `server/finding_verification.go:140`; thresholds `:27-29`; verbatim quote match `:162` | **Real and strict — fails closed** |
| 11 | Evidence binding (content-addressed blobs) | `evidence/store.go:33` hash path, `:43` sha256 verify, `:63` `.staging` + fsync + rename, `:182` `Record`, `:197` `Bind`, `:247` `OpenBody`, `:406` `RunGC` | Real |
| 12 | Asset graph | `db/assets.go:94` `Assets()`; `db/task_scope.go:360` `TaskCoverage`, `:455` `BuildCoverageGraph`, `:684` `ListUntestedAssets` | Real |
| 13 | Per-task exploration graph | `db/exploration.go:226` `AddNode`, `:290` `AddIntent`, `:1301` `ClaimIntent`, `:1433` `AppendActivity`, `:1240` `Frontier` | Real |
| 14 | Hot/cold graph folding | `agent/coldgraph.go:45` `defaultColdParams() {R:6,K:2}` — pure algorithms, DB-independent | Real |
| 15 | Traffic capture + search + ranged blobs | `traffic/traffic.go:939` `BlobRange`, `:989` `Search`, `:1082` page, `:1173` `Get`; FTS5 `:125` | Real |
| 16 | Traffic rewrite | `traffic/traffic.go:395` `SetRewriteRules`; `traffic/rewrite_flow.go` | Real |
| 17 | Tool-call interception / approval gate | `intercept/intercept.go:1`; `target_gate.go`, `closed_judge.go`, `argv.go`, `alwaysallow_denylist.go`, `risk.go`; schema `db/schema.sql:1073` | Real, unusually deep |
| 18 | Skills / playbooks | 21 dirs under `skills/`; per-agent visibility seeds `db/db.go:404` + `:438`; file editing API `server/server.go:975-987` | Real |
| 19 | Knowledge corpus | `knowledge/knowledge.go:30` `//go:embed data/*.json`; `Load()` `:73` (sync.Once); 22 JSON files | Real |
| 20 | Multi-provider LLM failover | `llmpool/pool.go:49` `Pool`, `:130` `Complete`, `:231` `shouldFailover`, `:254` hard failures; `llmpool/health.go`; `llmrec/` | Real |
| 21 | Reporting (task report) | `report/report.go:67` `Markdown`; `report/quality.go` | Real |
| 22 | Findings export | `server/server.go:2377` handler; formats `md-single` `:2435`, `md-zip` `:2438`, `csv` `:2452`, `json` `:2455`, default 400 `:2470`; renderers `report/findings.go:38,95,127,146`; CSV hardening `:176`; evidence zip `server/finding_traffic_export.go:92` | Real, 4 formats only |
| 23 | Retests | `db/finding_retests.go:188` start, `:199` result, `:226` finish (seals verdict, updates triage in-txn); schema `db/schema.sql:1216`, one-active index `:1232` | Real |
| 24 | Trigger scheduler | `server/scheduler.go:37` 5 s tick, `:41` `Run`, `:117` `step`, `:134` `fireIntervals`; **triggers attach to CUSTOM agents only** `:21` | Real, narrow |
| 25 | Notifications | 6 outbound sinks `notify/notify.go:22-29` (dingtalk, feishu, wecom, webhook, telegram, email); delivery retry `server/server.go:899-906`; inbound: none | Real (outbound only) |
| 26 | Auth | `server/auth.go:585` username must equal literal `"EyeOfG0d"`; JWT subject is the constant `EyeOfG0d` `:190`; TTL `:28`; `requireAuth` `:287` is boolean-only | Real, single-tenant |
| 27 | Migration discipline | `db/migrate.go:20` embed, `:151` checksum rejection, `:162` append-only rejection; only `0001`–`0007` exist | Real, enforced |
| 28 | Static-export UI | `web/next.config.mjs:24` `output: "export"`, `:26` `trailingSlash`; SPA served **without** auth `server/webui_embed.go:21` | Real |

### Confirmed absences

| Missing | How confirmed |
|---|---|
| SARIF output | `sarif|SARIF` over `*.go` and `*.ts*` → **0 matches**; export switch is 4 arms + 400 default (`server/server.go:2434-2470`) |
| Tenant / org / user ownership | `db/schema.sql` for `tenant_id|org_id|user_id` → **0 matches**; only `role` is agent kind (`:797`, `:815`) and finding role `'supporting'` (`:1286`) |
| SSO / SAML / OIDC | `server/*.go` for `SAML|OIDC|openid` → **0 matches** |
| Inbound webhook / API-key auth | No route accepts a non-JWT credential; `requireAuth` exempts only `/api/auth/*` and `/api/health` (`server/auth.go:290`) |
| Jira / GitHub / GitLab / DefectDojo adapter | `notify/` for `jira|github|gitlab|defectdojo` → **0 matches** |
| Finding fingerprint / cross-run identity | `db/schema.sql:1184-1205` has `task_id, node_id, vulnclass, name, severity, status, asset_ids` — no hash; `db/findings.go` for `fingerprint|hash` → 0. `duplicate` is a manual status only (`db/findings.go:55`) |
| Scan-to-scan diff | `TaskDiff|CompareTasks|DiffFindings|FindingTrend` → **0 matches** |
| i18n | `web/src` for `i18n|useTranslation|next-intl` → **0 matches** |
| Per-role authorization | `requireAuth` (`server/auth.go:287`) never parses a role; no handler reads one |

---

## 3. The three genuine gaps

### Gap 1 — No principal, no ownership (highest cost, highest blast radius)

`EyeOfG0d` is a hardcoded username (`server/auth.go:585`) and the JWT subject is a constant (`:190`). `requireAuth` (`:287`) asks only "is this token valid?" — it attaches no principal to the request. No table has an owner column (§2 absences). The result: one token grants full destructive reach — `DELETE /api/task-archives/{id}` (`server/server.go:789`), `POST /api/tasks/control` (`:817`), `DELETE /api/assets` (`:834`), and every task's stored credentials (`GET /api/tasks/{id}/credentials`, `:782`).

This is the largest gap versus commercial platforms and the one already named in the buyer research (`buyer-pain-points.md:116`: "SSO/SAML, RBAC/multi-project isolation"). It is also the most expensive to close: it is a column on nearly every table plus a principal threaded through roughly every handler in `server/server.go:739-1042`.

### Gap 2 — Findings have no identity across runs, so "continuous" is impossible

`findings` (`db/schema.sql:1184-1205`) records `task_id`, `vulnclass`, `severity`, `asset_ids` — and nothing that says *"this is the same vulnerability as the one from last month."* `duplicate` exists only as a status a human picks (`db/findings.go:55`).

Retests (`db/finding_retests.go:199`) answer "is this specific finding still real" and do it well. Nothing answers "what is new, what persists, what was fixed since the previous run against this asset," because there is no join key between runs. Every scan starts from zero.

Commercially this is the difference between a tool you run once and a program you renew: the renewal metric is trend, not snapshot (`buyer-pain-points.md:118`). It is also cheapest to fix *now*, while finding volume is still low — the backfill only gets more expensive.

### Gap 3 — Output cannot leave the product in a form a pipeline consumes

Export is exactly `md-single`, `md-zip`, `csv`, `json` (`server/server.go:2434-2468`), mirrored in the UI union type (`web/src/app/(main)/function/findings/page.tsx:288`, `web/src/lib/api.ts:604`). Notifications are outbound-only chat sinks (`notify/notify.go:22-29`). There is no SARIF, no ticket creation, no CI gate, no way for CI to *trigger* EyeOfG0d (no inbound endpoint — §2).

The irony: EyeOfG0d's evidence chain is stricter than most tools that do emit SARIF. A verified finding already carries POE ≥ 3 and a verbatim quote checked byte-for-byte against the bound response body (`server/finding_verification.go:154-162`). That rigor is trapped behind formats no scanner reads.

### Honourable mention — recurring scans

`agent_triggers` (`db/schema.sql:1032`) supports an interval plus five event kinds, but binds to `agent_key` and is documented as custom-agent-only (`server/scheduler.go:21`, `db/triggers.go:9`). There is no "run *this task* every Monday." Cheapest of the four, and the natural amplifier for Gap 2.

---

## 4. Candidate features

Blast radius is graded **small** (≤3 files, no schema change), **medium** (schema + a handful of handlers), **large** (schema-wide + most handlers).

### A. SARIF export + signed evidence bundle — **small**

**What:** a fifth export arm emitting SARIF 2.1.0, plus an HMAC-signed manifest so a downstream system can prove the bundle wasn't altered in transit.

**Files**
- `report/sarif.go` *(new)* — pure `SARIF(fs []*db.DBFinding, now time.Time) []byte`, matching the signature style of `report/findings.go:38,146`.
- `server/server.go:2434` — one `case "sarif":` arm; reuse the existing temp staging (`:2417`) and `setDownload` (`:2429`).
- `server/server.go:2373` — extend the format list in the doc comment.
- `web/src/lib/api.ts:604` + `web/src/app/(main)/function/findings/page.tsx:288,1457` — radio option.
- *Optional:* `server/finding_traffic_export.go:92` — add `manifest.sig` to the zip.

**Why it is genuinely small:** filtering (`findingFilterFromQuery`, used at `server/server.go:2405`), staging, naming, and per-finding markdown all already exist. SARIF is a pure function `[]*db.DBFinding → []byte`, unit-testable with no DB.

**Risk:** rule-id drift. Derive `ruleId` from `knowledge.Class()` (`knowledge/knowledge.go:607`) so SARIF rules fold to the same canonical classes the coverage ledger uses (`db/coverage_ledger.go:114`) — otherwise the same bug appears as three rules.

---

### B. Finding fingerprint + scan diff — **medium**

**What:** stable identity per finding, then a `new / persisting / resolved` view between two tasks.

**Files**
- `db/migrations/0008_finding_fingerprint.sql` *(new)* — `ALTER TABLE findings ADD COLUMN IF NOT EXISTS fingerprint TEXT NOT NULL DEFAULT ''` + index. **Must** be a new file: editing ≤ `0007` fails the checksum check (`db/migrate.go:151`) and inserting out of order fails (`:162`).
- `db/schema.sql:1184` — same column in the `CREATE TABLE`, so fresh installs and upgraded installs converge (the documented pattern, `db/db.go:6`).
- `db/findings.go` *(new funcs)* — `ComputeFingerprint(vulnclass, assetKey, location string) string` (sha256 over a normalized tuple) and `DiffFindings(base, head int64) (added, persisting, resolved []*DBFinding, err error)`.
- `evidence/store.go:182` `Record` and `db/exploration.go:2278` `AddStandaloneFinding` — the only two write paths; both already run inside transactions.
- `server/server.go` near `:849` — `GET /api/exploration/findings/diff?base=&head=`.
- `web/src/app/(main)/function/findings/page.tsx` — a diff badge, not a new page.

**The hard part, honestly:** the tuple. `vulnclass` must be folded through `knowledge.Class()` (`knowledge/knowledge.go:607`) or "SQLi" and "SQL injection" fingerprint differently; the asset key must reuse `assetKey()` (`db/task_scope.go:431`) so it joins the coverage graph. Both normalizers exist — which is why this is medium rather than large.

**Blast-radius caveat:** the migration is cheap; a *wrong* fingerprint is worse than none, because it manufactures false "resolved" badges. Ship behind a "diff (beta)" label until a backfill over existing findings has been eyeballed.

---

### C. Scheduled task runs — **small to medium**

**What:** "run this task template every N days" — distinct from today's custom-agent triggers.

**Files**
- `db/schema.sql` beside `:1032` — new `task_schedules` (task-template id or task spec, `interval_sec`, `enabled`, `last_fire`), modelled directly on `agent_triggers` (`:1032-1052`).
- `db/task_schedules.go` *(new)* — `ListDueSchedules`, `MarkFired`, using the same watermark discipline as `server/scheduler.go:61` (`init` seeds watermarks so a restart doesn't mass-fire).
- `server/scheduler.go:117` `step` — call `fireTaskSchedules()` alongside `fireIntervals` (`:134`).
- `server/goals.go:28` `launchTask` — the launch path already exists and takes `(t *Task, seedText string, seedFirstIntent bool)`; no new engine code.
- `web/src/app/(main)/function/tasks/` — a schedule control on the template dialog (routes `/api/task-templates` at `server/server.go:761-764`).

**Why it is smaller than it sounds:** the scheduler already ticks every 5 s (`server/scheduler.go:37`) and the concurrency reconciler (`:53`) already prevents overlap. This is a table plus one function called from an existing loop.

**Dependency:** nearly worthless without **B**. Recurring scans that can't be diffed just produce N disconnected finding lists. Sequence B first.

---

### D. Scoped API tokens (RBAC-lite) — **small to medium**

**What:** `Authorization: Bearer eyeofg0d_…` accepted alongside JWT, with two scopes — `read` and `run` — where `run` may create and control tasks but cannot delete archives, mutate settings, or read credentials.

**Files**
- `db/migrations/0009_api_tokens.sql` — `api_tokens(id, name, scope, hash, created_at, last_used_at, revoked_at)`.
- `db/schema.sql` — matching `CREATE TABLE IF NOT EXISTS`.
- `server/auth.go:287` — a second credential branch in `requireAuth`; the handler signature does not change, so no handler churn.
- `server/server.go` near `:894` — settings CRUD for tokens.
- `web/src/app/(main)/system/settings/` — a card.

**Why not full RBAC:** that is a column on nearly every table plus a principal threaded through `server/server.go:739-1042` — a quarter-scale change yielding no visible product improvement until finished. Tokens solve the immediate, real need ("let CI run scans without letting CI delete things") at a fraction of the cost, and they are forward-compatible: when a principal model lands, a token becomes a principal with a scope.

---

### E. Operator-visible spend governance — **small**

**What:** budgets already exist and already block work (`agent/budget.go:107,230`); they are invisible and env-only (`:86-93`).

**Files:** migration + `db/schema.sql:520` (`tasks.budget_tokens`, `budget_turns`); `agent/budget.go:86` add a DB-sourced path beside `BudgetsFromEnv`; `server/server.go:894` settings; `report/report.go:67` surface `BudgetState.Line()` (`agent/budget.go:173`).

**Why include it:** cheapest feature here that turns an existing internal mechanism into something a buyer can see. "Spend tied to validated outcomes" (`buyer-pain-points.md:117`) is currently unanswerable in the UI, even though the raw data (`llmrec`, `db/exploration.go:1470` `TokenTotal`) is already recorded.

---

### Rejected candidates (and why)

- **PDF/HTML reporting** — cosmetic until an export target exists; `md-zip` + evidence bundle is already defensible.
- **Second LLM routing layer** — `llmpool` already does failover + rotation (`llmpool/pool.go:168`); adding another invites split-brain.
- **Bulk / auto verification** — would silently erode the only real differentiator. `verificationMinPOE=3` and the verbatim-quote check (`server/finding_verification.go:27,162`) are the product.
- **i18n** — no framework (`web/src` grep: 0 matches); it is a rewrite of every page, not a flag.

---

## 5. Architectural constraints that should drive selection

Each of these eliminates a class of design; none is a preference.

1. **The UI is a static export with no server runtime.**
   `web/next.config.mjs:24` `output: "export"`, `:26` `trailingSlash: true`, `:25` `images.unoptimized` (under `NEXT_EXPORT=1`). No Next API routes, no server actions, no middleware, no SSR. Every screen must `fetch(\`/api${path}\`)` (`web/src/lib/api.ts:137`). **Consequence:** no feature may depend on Next-side logic, Next-set cookies, or streamed HTML. A "signed share link" must be a Go handler serving bytes.

2. **The embedded SPA is public; only `/api` is protected.**
   `server/webui_embed.go:21`: "Public (no JWT) — auth is enforced client-side and on /api." **Consequence:** every new authorization must live in Go. A UI-only gate is not a gate. This is precisely why D (tokens in `requireAuth`) is the sane RBAC entry point.

3. **Two stores, independent commit orders.**
   PostgreSQL and the SQLite traffic sidecar (`traffic/traffic.go:251`) are not transactional together; the code documents the hazard (`traffic/traffic.go:1501-1502`, `:1876-1883`). **Consequence:** a cross-store feature must state which store wins and tolerate index lag.

4. **`schema.sql` is idempotent base; `migrations/` is append-only and checksummed.**
   `db/db.go:33` re-runs `schema.sql` every boot; `db/migrate.go:151` rejects an edited migration; `:162` rejects an inserted one. **Consequence:** every feature adds a new `NNNN_*.sql` (next: `0008`) *and* a matching `CREATE TABLE IF NOT EXISTS` in `schema.sql` — or fresh installs diverge from upgraded ones.

5. **One binary; assets are embedded, not mounted.**
   `//go:embed` for schema (`db/db.go:33`), knowledge (`knowledge/knowledge.go:30`), optionally UI (`server/webui_embed.go:18`). **Consequence:** new static data (SARIF taxonomies, report templates) belongs in an embedded package. Anything user-editable (skills) goes through the filesystem API (`server/server.go:975-987`) — the split is deliberate.

6. **Prompt text is data, not code.**
   Prompts are DB-seeded and runtime-editable (`agent/planner.go:410`; `/api/agents/{key}/prompt` at `server/server.go:938-950`; version list `:948`). **Consequence:** behavior changes should ship as a seeded prompt block + a tool — the pattern of `findingVerificationGuidance` (`agent/finding_workflow.go:153-156`) and `coverageLedgerBlock` (`agent/coverage_ledger.go:58`) — not a hardcoded string, which goes stale the moment an operator edits the prompt.

7. **New agent tools must enter through assembly.**
   `agent/assembly.go:61` `AugmentTools` composes base → `ToolAugment` hook (`:35`) → DB `ToolResolve` → ToolRAG → `findingWorkflowTools` → panic guard (`:90-100`). **Consequence:** a tool registered outside this path loses panic guarding and per-agent visibility (`db/db.go:404`).

8. **Verification is a hard gate.**
   `verificationMinPOE = 3` (`server/finding_verification.go:27`), quotes under 8 runes ignored (`:28`), 4 MB read cap (`:29`), verbatim match after whitespace normalization (`:162`), fails closed. **Consequence:** any feature needing a weaker bar needs a **new status**, not a lower threshold.

9. **No i18n layer.** `web/src` grep for `i18n|useTranslation|next-intl` → 0. Strings are inline. **Consequence:** localized builds are a rewrite, not a config flag. Don't promise them casually.

---

## 6. Recommended sequencing

| Order | Feature | Radius | Rationale |
|---|---|---|---|
| 1 | **A. SARIF export** | small | Pure function + one switch arm. Immediately converts the existing evidence chain into something CI and ticketing consume. |
| 2 | **B. Fingerprint + diff** | medium | Unlocks trend — the metric renewals depend on. Cheap now, progressively expensive as finding volume grows. |
| 3 | **C. Scheduled task runs** | small–medium | Reuses `launchTask` and the existing 5 s scheduler. Only meaningful after B. |
| 4 | **E. Spend governance in UI** | small | Turns existing budgets (`agent/budget.go`) into a legible control. |
| 5 | **D. Scoped API tokens** | small–medium | Unblocks CI without a schema-wide principal refactor. |
| later | **Full RBAC + projects** | large | Correct long-term answer to Gap 1; trigger on a real multi-team customer, not on speculation. |

**Not in this cycle:** PDF/HTML reports, i18n, a second LLM router, and anything that relaxes `server/finding_verification.go`.

---

## 7. What would invalidate this analysis

- If a fork or branch already carries `api_tokens` or `project_id`, D collapses into "finish it." Checked at `5ce5386` with a clean tree only.
- If SARIF is a hard contractual requirement rather than a nice-to-have, A is blocking and should ship *with* bundle signing, not after it.
- If the deployment model is one container per customer by design, Gap 1 is not a gap — drop D and D-lite entirely, and spend the budget on B + C.
- If `findings` volume is already large, B's backfill becomes an online-migration problem (batched, resumable) rather than a one-shot `UPDATE`, which upgrades B from medium toward large.
