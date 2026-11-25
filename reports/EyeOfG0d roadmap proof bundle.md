# EyeOfG0d roadmap: a new feature proposal

**Question:** Which new feature should EyeOfG0d build next, given the goal of growing the open-source
project, a 1–2 month budget, and a desire to strengthen autonomy quality, trust/evidence, integration,
compliance and platform-ops at once?

**Recommendation: ship a portable, self-verifying evidence bundle — and diff it.**

---

## 1. Why this is the right answer

Every piece of research pointed at the same asymmetry. EyeOfG0d's differentiator is that it *binds every
finding to the traffic that proves it* — and that is real in the code: content-addressed blobs,
sha256-verified on read (`evidence/store.go:120,182`), verbatim-quote verification that fails closed
(`server/finding_verification.go:154,162`), retests with `reproduced/fixed/inconclusive`
(`db/finding_retests.go:199`). The product already does the hard thing.

But that proof never leaves the building in a form anyone else can check. It lives in a database and in
a `md-zip` folder (`server/server.go:2435`) that a recipient has to *trust*. Meanwhile:

- **Buyers don't trust AI findings.** 87.8% of practitioners still require significant manual validation;
  willingness to rely on fully autonomous pentesting fell 29% → 9% year over year; 78% saw automated tools
  miss critical vulnerabilities. The blocker is not detection rate, it is *unverifiable output*.
- **Commercial leaders' proof is vendor-internal.** XBOW, NodeZero and Pentera differentiate on validated
  exploit paths, but no one exposes a **portable, replayable evidence artifact**. That is the whitespace.
- **Findings that don't leave the tool don't get fixed.** Workflow disconnection is the named reason
  pilots die. SARIF + JSON is the cheapest possible fix and is a format contributors already know.
- **Regulation now asks for exactly this.** CRA reporting obligations begin 11 Sep 2026 (main obligations
  11 Dec 2027); DORA TLPT has applied since 17 Jan 2025; PCI DSS 4.0 Req 11.4 requires methodology,
  findings, remediation and **retest**. All of them want a baseline → finding → fix → retest timeline with
  per-finding artifacts. That is a bundle over time. It is not a PDF.
- **The OSS field has continuity risk.** `aliasrobotics/cai` is already archived and read-only, with a
  successor named. Flexibly-hosted OSS agents are plentiful; durable, verifiable ones are not.

And the growth argument, which matters most given the goal: **a stranger cannot try EyeOfG0d today.** It
needs Postgres, an LLM key that costs money, and a target with legal exposure, and then a scan that takes
tens of minutes. There is no five-minute moment. A self-verifying bundle creates one — you can verify a
recorded engagement offline, in seconds, with no key and no target.

## 2. What it is, concretely

**A `.eyeofg0d` bundle** — a single file (or directory) containing an engagement's findings, the bound
traffic evidence, the coverage ledger, and a manifest of sha256 digests.

```
eyeofg0d bundle export --task 42 > acme-web-2026-11.eyeofg0d
eyeofg0d bundle verify acme-web-2026-11.eyeofg0d      # green: 47 findings, 312 blobs, all hashes valid
eyeofg0d bundle diff q3.eyeofg0d q4.eyeofg0d             # new / persisting / resolved / regressed
```

Three properties do the work:

1. **Portable.** One file. It moves between instances, survives an air gap, can be attached to a ticket or
   handed to an auditor. No database required to read it.
2. **Self-verifying.** Every blob's digest is in the manifest; `verify` recomputes and reports. The
   recipient does not have to trust the sender — that is the entire point of "keeps its receipts".
3. **Diffable.** Because findings carry a stable fingerprint, two bundles answer the only question the
   second visit cares about: *what changed?*

This is a synthesis, not a fantasy: `md-zip` already stages `evidence/<fid>/<bid>/*`, the blob store is
already content-addressed and sha256-verified, and `knowledge.Class()` already canonicalises vulnclasses.
The bundle is those primitives given a wire format and a verifier.

## 3. Scope over 1–2 months

| Phase | Work | Effort |
| --- | --- | --- |
| **1. Bundle format + export** | Manifest schema, `bundle/` package, export path reusing `StageFindingsExport` | 2 wks |
| **2. Offline verifier** | `eyeofg0d bundle verify`, digest recompute, human + `--json` output | 1 wk |
| **3. Fingerprint** | `findings.fingerprint` via `db/migrations/0008_*.sql`; pure function over canonicalised inputs | 2 wks |
| **4. Bundle diff** | Four buckets; refuses `resolved` on an incomplete run | 1.5 wks |
| **5. SARIF + CI** | SARIF inside the bundle; a GitHub Action that verifies and gates | 1.5 wks |
| **— Demo bundle** | Ship one recorded engagement in the repo; import → populated UI, no key needed | 3 days |

Roughly 8 weeks with tests and docs. Phases 1–2 alone are already a shippable, demoable artifact, which
de-risks the schedule: if the fingerprint turns out to be contentious, the bundle still stands alone.

**Deferred on purpose:** recurring scheduled scans (scheduling without diffing just produces more isolated
findings — it is only valuable *after* phase 4).

## 4. How it scores against your five axes

| Axis | How the bundle strengthens it | Depth |
| --- | --- | --- |
| **Trust & evidence** | The core. Integrity becomes checkable by the recipient, not asserted by the sender. | Deep |
| **Integration & workflow** | SARIF + JSON + a CI verifier step; the bundle is the thing you attach to a ticket. | Real |
| **Compliance & reporting** | Auditable artifact with timestamps, digests, retention and drift history — maps to PCI 11.4 retest and CRA/DORA evidence. | Real |
| **Platform & ops** | Air-gapped handoff between instances; pure Go, no new services, stays a single binary. | Real |
| **Autonomy quality** | The diff inherits the coverage-completeness caveat, so it can never claim "resolved" off a partial run — it makes existing rigor compound instead of resetting. | Moderate |
| **OSS growth** (your goal) | Zero-cost 60-second demo; a *format* contributors can extend (verifiers, importers, renderers in any language). | Strong |

Note what it is *not* doing: it does not make the agent smarter. That is the honest tradeoff, and it is the
right one — see §6.

## 5. The failure mode, stated plainly

**Fingerprint instability.** If the identity churns between runs, every scan looks like total churn, the
diff becomes noise, and the feature destroys the trust it was built to create. Mitigations:

- Hash only canonicalised inputs — never LLM-written prose (no finding name, no summary; those vary).
- Ship behind a stability test: replay N recorded runs, assert zero false churn.
- When identity is ambiguous, emit `unstable` and bucket it separately. "I can't tell" is survivable;
  a confident lie is not.

This is the same discipline as `assessFindingVerification`: fail closed, never inflate.

A second risk: **format lock-in.** Once bundles are distributed, the schema is hard to change. Mitigate
with an explicit `version` field and a documented upgrade path from day one.

## 6. Alternatives considered, and why not

**Agent-quality work (planner pruning, shared memory, TDA-style search).** The research is genuinely
strong — PentestGPT v2's difficulty-aware search reports 91% peak on XBOW, Red-MIRROR's persistent memory
86%, and prompt caching cuts cost 41–80%. But: it needs an LLM key and a real target to demonstrate, it is
invisible in a screenshot, and **it cannot be verified in this repo** without a benchmark harness. It makes
the product better and the project no more adopted. Revisit once there is a scoring rig.

**Benchmark harness / published scoreboard.** Highest marketing value of anything on this list — "EyeOfG0d
scores X on Cybench/AutoPenBench" is a press release. But it is orthogonal to all five axes you picked, it
costs real money per run, and it is research work rather than product work. **Do it next, not now.**

**Finding diff only (no bundle).** Cheaper, but it has no zero-cost demo and no zero-trust handoff. The
bundle is what makes the diff legible to someone who was not there.

**Full RBAC / SSO / multi-tenancy.** The real gap versus commercial platforms — and the wrong thing now.
`EyeOfG0d` is a hardcoded username (`server/auth.go:585`), the JWT subject is the constant `"EyeOfG0d"`
(`server/auth.go:190`), and no role or tenant column exists anywhere. Threading a principal through
`requireAuth` touches essentially every handler and contradicts the deliberate client-side-auth model
(`server/webui_embed.go:21`). That is a quarter, and a rewrite of the auth boundary. A cheap slice —
**named API tokens with `read-only` / `operator` scope** — fits inside the bundle work and unblocks CI.

**More skills/playbooks.** The repo already ships 21 skill directories. This is a content game with
diminishing returns; the corpus was just expanded and is not the constraint.

## 7. What success looks like at 2 months

- `eyeofg0d bundle verify` exists and is referenced in the README quick start
- A recorded demo bundle ships in the repo and imports into a populated UI with no LLM key
- `eyeofg0d bundle diff` answers new/persisting/resolved on two real runs
- SARIF export lands in a GitHub Action example
- The bundle format is documented well enough that someone files an issue asking to write a Python verifier

That last bullet is the one that measures whether this grew the project or just improved it.

## Sources

Competitive landscape, buyer pain points, agent techniques and regulatory drivers are captured in
`research_notes/EyeOfG0d roadmap feature proposal/`. Codebase claims are grounded with `file:line`
citations in `codebase-gap-analysis.md`.
