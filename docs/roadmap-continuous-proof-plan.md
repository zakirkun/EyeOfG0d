# Work plan: Continuous Proof

**Branch:** `feat/continuous-proof` (to be created off `main`)
**Estimate:** ~9 weeks · **Decisions locked:** diff is the hook · fingerprint as a column · diff endpoint
only (no gate endpoint) · full scoped API tokens

---

## 0. Confirmed extension points

Verified against the tree at `65045ef`, not taken from summaries:

| Fact | Where |
| --- | --- |
| Migrations stop at `0007`; embedded via `//go:embed migrations/*.sql` | `db/migrate.go:20`; `db/migrations/` |
| Export format switch, 4 cases + default 400 | `server/server.go:2434-2471` |
| Evidence staging already exists and is reused by every format | `server/server.go:2423` → `evidence.Store.StageFindingsExport` |
| `findings` table: id, task_id, node_id, vulnclass, name, severity, summary, evidence, worker, asset_ids, status, report, created_at | `db/schema.sql` (`CREATE TABLE IF NOT EXISTS findings`) |
| Auth: literal `req.Username != "EyeOfG0d"`, boolean `requireAuth` | `server/auth.go:585`, `server/auth.go:287` |
| `jwtSubject` already parses and returns a subject | `server/auth.go:249` |

---

## Phase 1 — Fingerprint (2 weeks)

**Goal:** every finding gets a stable identity that survives re-runs.

1. `db/migrations/0008_finding_fingerprint.sql`
   ```sql
   ALTER TABLE findings ADD COLUMN IF NOT EXISTS fingerprint TEXT NOT NULL DEFAULT '';
   CREATE INDEX IF NOT EXISTS idx_findings_fingerprint ON findings (fingerprint) WHERE fingerprint <> '';
   ```
   Also mirror the `ADD COLUMN IF NOT EXISTS` in `db/schema.sql` so a fresh boot has it before migrations.
   **Never edit `0001`–`0007`** (`db/migrate.go:158-166`).

2. `db/fingerprint.go` — pure function:
   ```go
   func FindingFingerprint(vulnclass, assetKey, location string) string
   ```
   - `vulnclass` → `knowledge.Class()` canonical form (`knowledge/knowledge.go:607`)
   - `assetKey` → existing normaliser (`db/task_scope.go:431`)
   - `location` → stable discriminator (normalised path/param), caller-supplied
   - `sha256` of the three joined with `\x1f`. **No prose, no name, no summary, no severity.**
   - Returns `""` when `vulnclass` canonicalises to empty and `location` is empty → the caller writes
     `fingerprint_unstable` instead of inventing one.

3. Write at both finding-write paths:
   - `evidence/store.go:182` (`Record`)
   - `db/exploration.go:2278` (`AddStandaloneFinding`)

4. `db/fingerprint_test.go` — table-driven: same inputs stable; `SQLi`/`sqli`/`SQL injection` collapse to
   one; differing locations differ; empty inputs → unstable. **This test is the gate on the whole feature.**

**Exit criteria:** fingerprint populated on new findings, stable across two runs of the same scan fixture.

---

## Phase 2 — Diff (2.5 weeks)

**Goal:** answer new / persisting / resolved / regressed between two tasks.

1. `db/findings.go` — `DiffFindings(ctx, baseTaskID, headTaskID) (*FindingDiff, error)` beside
   `ListFindingsForExport` (`db/findings.go:514`).

   ```go
   type FindingDiff struct {
       New, Persisting, Resolved, Regressed []FindingDiffEntry
       BaseComplete, HeadComplete bool   // coverage completeness of each side
       ResolvedTrustworthy        bool   // false unless HeadComplete
   }
   ```

2. **Honesty rule (non-negotiable):** if the head run's `CoverageCompleteness.Complete` is false
   (`db/coverage_ledger.go:353`), `ResolvedTrustworthy` is false and the response says so. A partial scan
   that "proved" a fix is worse than no diff. Same discipline as verification failing closed
   (`server/finding_verification.go:154`).

3. `server/server.go` — `GET /api/tasks/{id}/diff?base={id}` registered beside the coverage routes
   (`server/server.go:791-793`). Returns JSON. Self-authorizes via `requireAuth`, per the constraint that
   the embedded UI handler is public (`server/webui_embed.go:21`).

4. UI: a `Diff` tab under `web/src/app/(main)/function/tasks/detail/_tabs/`. Table of four buckets, with a
   banner when `!ResolvedTrustworthy`.

**Exit criteria:** diff of two fixture runs returns correct buckets; a deliberately truncated head run
refuses to claim `resolved`.

---

## Phase 3 — Bundle export + verifier (2.5 weeks)

**Goal:** one portable file that a stranger can check without trusting the sender.

1. `bundle/` package (new):
   ```
   manifest.json   // version, created_at, task meta, coverage ledger, findings[], blobs{digest:size}, rootDigest
   findings.json   // full finding records incl. fingerprint, PoE, verification status
   evidence/<fid>/<bid>/req|resp
   README.txt      // how to verify, one paragraph
   ```

2. `bundle/export.go` — builds from a task; reuses `StageFindingsExport` (`server/server.go:2423`) for
   blob staging rather than re-reading the store. Tar + gzip, deterministic ordering and timestamps so two
   exports of the same task are byte-identical (this makes the digest meaningful).

3. `bundle/verify.go` — recomputes every blob digest, checks `rootDigest` over `manifest.json`, returns
   structured results:
   ```go
   type VerifyResult struct { OK bool; Findings, Blobs int; Bad []string; Warnings []string }
   ```

4. Entry points:
   - `GET /api/tasks/{id}/export?format=bundle` — one case in the switch (`server/server.go:2434`)
   - CLI subcommand in `cmd/eyeofg0d/main.go` (`-verify <file>`, `-diff <a> <b>`) so it works air-gapped with
     no server running

5. **Import** — `POST /api/bundles/import` creates a read-only task view. This is what makes the demo
   work without an LLM key.

**Exit criteria:** export → delete server DB → `eyeofg0d -verify` passes offline; tamper one blob byte →
verify fails with the right message.

---

## Phase 4 — SARIF (1 week)

`report/sarif.go` — `FindingsSARIF(fs []*db.DBFinding) []byte`:
severity → `level` (critical/high = `error`, medium = `warning`, low = `note`), vulnclass → `ruleId`,
assets → `artifactLocation`, bound evidence → `attachments` pointing at the staged bytes.
One case in the format switch (`server/server.go:2434`); widen the UI union
(`web/src/lib/api.ts:604`) and add a radio on the findings page. **No DB change.**

---

## Phase 5 — Scoped API tokens (1.5 weeks)

**Scope note:** this is larger than the read-only sliver — tokens with expiry and audit are a small
subsystem, not a one-file change.

1. `db/migrations/0009_api_tokens.sql`:
   ```sql
   CREATE TABLE IF NOT EXISTS api_tokens (
       id BIGSERIAL PRIMARY KEY,
       name TEXT NOT NULL,
       token_hash TEXT NOT NULL UNIQUE,   -- sha256, never the token itself
       scope TEXT NOT NULL DEFAULT 'read_only',  -- read_only | operator
       created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
       expires_at TIMESTAMPTZ,
       last_used_at TIMESTAMPTZ,
       revoked_at TIMESTAMPTZ
   );
   ```

2. `server/tokens.go` — create (returns plaintext **once**), list (hash only), revoke.
3. Extend `requireAuth` (`server/auth.go:287`): if the bearer value is not a JWT, hash it and look it up;
   attach scope to the request context. Then a `requireScope(ctx, "operator")` guard on destructive routes
   (`/api/tasks/control`, `DELETE /api/task-archives/{id}` — `server/server.go:779,789`).
4. UI: a tokens card under `system/settings`.

**Exit criteria:** read-only token gets 403 on task control; expired token 401; plaintext never persists.

---

## Phase 6 — Demo + docs (0.5 week)

- Record one real engagement; commit `examples/demo-eyeofg0d-bundle.tar.gz`.
- README quick start gains a 60-second path: `eyeofg0d -import examples/demo…` → populated UI, no key.
- `docs/bundle-format.md` — versioned schema, upgrade path, and a "write your own verifier" section.

---

## Sequencing rationale

Phases 1–2 are the hook and are independently shippable at ~week 5. Phase 3 makes the diff legible to
someone who wasn't there. Phase 4 is the cheapest integration win and rides existing staging. Phase 5 is
last because it touches auth and nothing before it depends on it — if the cycle overruns, it is the clean
thing to cut.

## Test plan

- `db/fingerprint_test.go` — table-driven stability (the feature gate)
- `db/findings_test.go` — diff buckets incl. the incomplete-head refusal
- `bundle/*_test.go` — round-trip, tamper detection, determinism (byte-identical re-export)
- `server/*_test.go` — endpoint auth, scope enforcement, format switch
- Replay test: two runs of a recorded fixture must produce identical fingerprints

## Risks

| Risk | Mitigation |
| --- | --- |
| Fingerprint churn | Pure function, no prose, replay test gates the UI |
| Bundle format lock-in | `version` field + documented upgrade path from day one |
| Scope creep into full RBAC | Tokens only; `requireAuth` gains a lookup, not a principal model |
| Auth regression | Phase 5 last, isolated, with its own tests; existing JWT path untouched |

## Not in scope

Full RBAC/multi-tenancy/SSO · PDF/HTML rendering · i18n · agent-orchestration changes · benchmark harness
(separate track, run next).
