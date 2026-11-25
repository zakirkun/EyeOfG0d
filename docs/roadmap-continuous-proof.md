# Roadmap proposal: Continuous Proof

**Status:** proposal for discussion · **Target:** 1–2 months · **Primary goal:** grow OSS adoption

---

## 1. The recommendation in one paragraph

Ship **Continuous Proof**: give every finding a stable fingerprint, diff any two runs of the same asset
(`new / persisting / resolved / regressed`), and export the result as **SARIF** and JSON alongside the
existing markdown/CSV. The platform already proves a finding is real *right now* — verbatim-bound
evidence, POE ≥ 3, retests with `reproduced/fixed/inconclusive`. What it cannot answer is the question
every buyer actually asks on the second visit: **"what changed since last time?"** Today each run is an
island (`findings` has no fingerprint column at all), so the rigor resets to zero every scan. Closing that
gap converts a point-in-time tool into a continuous one, and it does so on top of machinery that already
works rather than beside it.

## 2. What the evidence says

Four research streams fed this; the decision-relevant findings:

**Trust is the adoption blocker, and proof is the answer — but proof is not portable anywhere yet.**
87.8% of practitioners still require significant manual validation of AI findings, and willingness to rely
on fully autonomous pentesting fell from 29% to 9% year over year; 78% saw automated tools miss critical
vulnerabilities. Commercial leaders (XBOW, NodeZero, Pentera) do differentiate on validated exploit paths
and retest loops, but their "proof" is largely vendor-internal. No one exposes a **portable, replayable
evidence artifact** as a first-class output. That is precisely where EyeOfG0d's architecture already sits.

**The autonomy leaders are cloud-bound and opaque.** XBOW and NodeZero show no documented self-host or
air-gapped path. The OSS agent wave (PentestGPT, Strix, Hexstrike) is flexible but evidence is
trace-dependent and ad hoc, and the space has continuity risk — `aliasrobotics/cai` is already archived.
Self-hosted + model-agnostic + evidence-first is genuinely underserved.

**Findings that never leave the tool do not get fixed.** Workflow disconnection is named repeatedly as
the reason pilots die: findings stranded outside Jira/GitHub/CI become shelfware. SARIF + a JSON feed is
the cheapest possible fix and it is a well-known format, which matters for both adoption and contribution.

**Regulation now demands exactly this shape of artifact.** CRA reporting obligations begin **11 Sep 2026**
(three weeks from now) with main obligations 11 Dec 2027; DORA has applied since 17 Jan 2025 including
TLPT; PCI DSS 4.0 Req 11.4 requires documented methodology, findings, remediation and **retest**. Every one
of them asks for the same thing: a **baseline → finding → fix → retest timeline with per-finding artifacts**.
That is a diff over time. It is not a PDF.

## 3. The gap this closes

The codebase is unusually well-built on the "is this finding real" axis, and unusually empty on the
"did this change" axis. Concretely:

| Already strong | Evidence |
| --- | --- |
| Verbatim-quote verification, fails closed | `server/finding_verification.go:154,162` |
| Content-addressed evidence blobs, sha256-verified | `evidence/store.go:120,182` |
| Retests with reproduced/fixed/inconclusive | `db/finding_retests.go:199` |
| Coverage completeness caveat (partial runs admitted) | `db/coverage_ledger.go:338,353` |

| Missing | Proof of absence |
| --- | --- |
| Any finding identity across runs | `db/schema.sql:1184-1205` — no fingerprint/hash/dedupe column |
| Any compare/diff function | none in `db/` or `server/` |
| SARIF or any machine-readable export | `server/server.go:2434` accepts exactly 4 formats, no SARIF |

The retest feature already answers "is this *one* finding still real". Nothing answers "which findings are
new this week". Those are different questions and the second is the one that gets renewed.

## 4. Why this and not the alternatives

Scored against the goal you set (grow the OSS project) rather than against feature completeness:

| Candidate | Time to first value | Demo surface | Contributor seam | Axes touched | Effort honesty |
| --- | --- | --- | --- | --- | --- |
| **Continuous Proof (A+B+C)** | Minutes: two scans, one table | **Very high** — "Monday scan, patch, Tuesday scan, here's what closed" | **Strong** — fingerprint is a pure function with a test table | 5/5 | 6–8 weeks, realistic |
| SARIF export alone | Minutes | Low — a file download | Good | 2/5 | 1 week, too small for the slot |
| Agent quality (planner/blackboard/TDA) | Days — needs an LLM key and a real target | Low — invisible in a screenshot | Weak | 1/5 | 4+ weeks, unverifiable without a benchmark |
| Benchmark harness ("we score X on Cybench") | Hours for a reader | **Highest** of any option | Medium | 1/5 | 4+ weeks, and it helps nobody's actual work |
| Full RBAC / multi-tenant | Days, and only for enterprise | None | Weak | 2/5 | **Quarter+, and it contradicts the deployment model** |

**On the agent-quality option** — it is the most tempting and the worst fit. The research is clear that
planner improvements pay off (PentestGPT v2's difficulty-aware search reports 91% on XBOW; Red-MIRROR's
shared memory reports 86%), but none of that is demonstrable to a stranger without a benchmark, and it
cannot be verified in this repo today. It makes the product better and the project no more adopted.

**On the benchmark harness** — this is the single highest-leverage *marketing* artifact available in this
space right now. I am deliberately separating it: it is a research track to run *after* this feature, not
a substitute for it, because it is orthogonal to every axis you selected.

**On RBAC** — the codebase analysis is blunt and I agree with it: `EyeOfG0d` is a hardcoded username
(`server/auth.go:585`), the JWT subject is the constant `"EyeOfG0d"` (`server/auth.go:190`), and no role or
tenant column exists anywhere in the schema. Threading a principal through `requireAuth` touches
essentially every handler and contradicts the deliberate client-side-auth model
(`server/webui_embed.go:21`). It is the biggest genuine gap versus commercial products and the wrong
thing to build now. The cheap 80% — **named API tokens with a `read-only` / `operator` scope** — fits
inside this feature and unblocks CI, so I fold a sliver of it in.

## 5. Scope: what ships in 1–2 months

**Phase 1 — Fingerprint (2 weeks).** Add `findings.fingerprint TEXT` via `db/migrations/0008_*.sql`
(first real migration; `schema.sql` stays idempotent and `0001`–`0007` are untouchable per
`db/migrate.go:158-166`). Compute from canonical `vulnclass` via `knowledge.Class()`
(`knowledge/knowledge.go:607`) + normalized asset key (`db/task_scope.go:431`) + stable location
discriminator. Written at both finding-write paths (`evidence/store.go:182`,
`db/exploration.go:2278`). **Pure function, table-driven tests.**

**Phase 2 — Diff (2–3 weeks).** `DiffFindings(baseTaskID, headTaskID)` in `db/findings.go` beside
`ListFindingsForExport` (`db/findings.go:514`), returning four buckets. It **must refuse to claim
`resolved` when the head run is incomplete**, reusing `CoverageCompleteness.Complete`
(`db/coverage_ledger.go:353`) verbatim — a partial scan that "proved" a fix is worse than no diff.
Endpoint `GET /api/tasks/{id}/diff?base={id}` next to the coverage routes (`server/server.go:791-793`).
One UI tab under `function/tasks/detail/_tabs/`.

**Phase 3 — Export (1–2 weeks).** `report/sarif.go` mapping severity → SARIF `level`, `vulnclass` →
`ruleId`, assets → locations, bound evidence → attachments pointing at staged bytes. One case in the
format switch (`server/server.go:2434`). Widen `web/src/lib/api.ts:604` and add a radio on the findings
page. JSON diff feed alongside it. **No DB change.**

**Phase 4 — Optional, if time remains.** Lightweight API token with `read-only` scope so CI can call the
diff endpoint without operator rights. Extend `requireAuth` (`server/auth.go:287`) only.

Recurring scheduled runs are **deliberately deferred**: scheduling without diffing just produces more
isolated findings, and the diff is what makes a schedule meaningful.

## 6. The one thing that can kill this

**Fingerprint stability.** If the hash churns between runs, every scan looks like total churn, the diff
becomes noise, and the feature actively damages trust — the exact failure it was meant to prevent. So:

- The hash is a **pure function** over canonicalized inputs only. **No LLM-written prose may enter it** —
  not the finding name, not the summary. Those are exactly the fields that vary run to run.
- Ship it behind a **stability test**: replay N recorded runs and assert zero false churn before the UI
  is allowed to show a diff.
- When the fingerprint is genuinely unknown (unusual vulnclass, ambiguous location), emit `unstable` and
  bucket it separately rather than guessing. A diff that says "I can't tell" is survivable; one that lies
  is not.

This mirrors the discipline already in `assessFindingVerification` — fail closed, never inflate.

## 7. Explicitly not in scope

Full multi-tenant RBAC and SSO (quarter+, contradicts client-side auth); PDF/HTML report rendering
(cosmetic until export targets exist); i18n (not a self-hosted blocker); agent-orchestration rewrites
(unverifiable here, invisible to a newcomer); benchmark publication (separate track, high value, do it next).

## 8. Open questions for discussion

1. **Is the demo actually convincing?** My premise is that "what closed since last scan" is the hook. If
   you think a newcomer's first question is something else, that changes the ranking.
2. **Does the fingerprint belong on `findings` or on a separate table?** Column is simpler; a table keeps
   history across renames. I lean column now, table if renames turn out to be common.
3. **Should the diff endpoint be the CI gate, or should there be a separate `gate` endpoint** that returns
   exit-code semantics (`fail on: new critical`)? The former is one endpoint; the latter is the thing CI
   actually wants.
4. **How much of Phase 4 do you want?** Read-only API tokens are small and make the CI story real, but
   they are the only piece here that touches auth.

Once you pick, I'll write the work plan (file-by-file, with tests) before any implementation starts.
