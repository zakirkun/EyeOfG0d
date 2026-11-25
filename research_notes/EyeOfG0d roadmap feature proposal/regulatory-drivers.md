# Regulatory & Compliance Drivers for Automated, Evidence-Backed Pentest Artifacts (2025-2026)

**Prepared for:** EyeOfG0d roadmap (records real HTTP traffic as evidence per finding)  
**Status:** Research note, current as of **2026-11-19** (dates/timelines verified against official sources cited below).  
**Scope:** EU CRA, NIS2, DORA, SEC cyber disclosure, PCI DSS 4.0 (11.4), ISO 27001, SOC 2, HIPAA.

## Cross-cutting: "Pentest report" vs "compliance evidence"

| Dimension | Traditional pentest report | Compliance-grade evidence (automation opportunity) |
|---|---|---|
| Content | Narrative PDF: scope, findings, screenshots, recommendations | Immutable evidence bundle: scoped assets/tests, timestamped raw request/response or traffic traces, tool/config versions, tester identity/authorization, finding-to-evidence linkage, remediation & retest results |
| Verifiability | Hard to independently replay; screenshots can be ambiguous | Reproducible traces (e.g., HTTP transcripts/pcaps/logs), hashes, chain-of-custody metadata, deterministic test IDs |
| Format | Mostly human-readable PDF/Word | Dual output: human report + machine-readable (JSON/CSV/SARIF/OSCAL-like mappings) for GRC ingestion and regulator/auditor portals |
| Integrity & sign-off | Wet/digital signature on PDF; limited provenance | Cryptographic signing/attestation of scope, results, and evidence package; role-based approvals; tamper-evident audit trail |
| Change linkage | Point-in-time snapshot | Continuous/triggered runs tied to releases/significant changes; diffable results over time |
| Retention | Ad hoc storage | Policy-driven retention/WORM options, versioned artifacts, exportable audit packages |

**EyeOfG0d fit:** per-finding recorded real HTTP traffic can serve as primary technical evidence, enabling replayable proof, machine-readable export, and signed evidence bundles that close the gap between consultant narrative and auditor/regulator-ready proof.

---

## 1. EU Cyber Resilience Act (CRA) - Regulation (EU) 2024/2847

- **Official source:** [EUR-Lex CELEX:32024R2847](https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX:32024R2847)
- **Status/timeline (precise):** Entered into force **10 December 2024**. **Article 14 reporting obligations** (actively exploited vulnerabilities and severe incidents by manufacturers) apply from **11 September 2026**. **Main obligations apply from 11 December 2027** (with earlier application of certain conformity/notification provisions as specified).
- **Testing/vulnerability-handling obligations:** Secure-by-design/default lifecycle duties (Art. 13, Annex I Parts I-II), vulnerability handling processes, coordinated vulnerability disclosure, security updates, and due diligence on integrated components. Conformity assessment requires technical documentation demonstrating compliance (Annex VII/VIII as applicable); important/critical product classes may require stricter or third-party assessment routes.
- **Mandate vs incentive:** **Mandatory** for in-scope "products with digital elements" made available on the EU market.
- **Artifacts/evidence expected:** Technical documentation; vulnerability handling policy/process records; SBOM and component inventory (available to authorities as required); test/verification and secure development evidence; incident/vulnerability reports submitted via the single reporting platform per Art. 14; update/support period documentation; conformity assessment records and EU declaration of conformity.
- **Format/attestation/retention:** Technical documentation made available to market surveillance authorities and retained in line with CRA conformity-documentation and support-period duties. Incident reports submitted through authority-specified digital channels. Attestation via EU declaration of conformity and notified-body involvement where required.
- **Automation opportunity:** Generate traceable security test evidence mapped to Annex I requirements; maintain versioned per-release evidence packs; auto-produce structured vulnerability/incident-ready records and SBOM-linked findings; signed, time-stamped test artifacts supporting conformity files and post-market surveillance.

## 2. NIS2 Directive - Directive (EU) 2022/2555

- **Official source:** [EUR-Lex CELEX:32022L2555](https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX:32022L2555)
- **Status/timeline (precise):** Entered into force **16 January 2023**. **Transposition deadline: 17 October 2024**. Member States to **apply measures from 18 October 2024** (national implementation/enforcement varies).
- **Testing/audit obligations:** Art. 21 requires appropriate and proportionate cybersecurity risk-management measures, including policies and procedures to **assess the effectiveness** of measures (e.g., testing and audits), secure development/acquisition and vulnerability handling/disclosure, incident handling, BCP, supply chain security, etc. Arts. 32-33 provide supervisory and enforcement powers (audits/inspections).
- **Mandate vs incentive:** **Mandatory** for in-scope essential and important entities (as implemented in national law).
- **Artifacts/evidence expected:** Risk assessments; policies; results of effectiveness testing/audits and reviews; vulnerability management records; incident reports per Art. 23 timelines (early warning/notification/final report); training and governance records; supplier/security evidence.
- **Format/attestation/retention:** National CSIRT/competent-authority reporting channels (often structured portals); records must be producible for inspections and enforcement. Management accountability (Art. 20) implies documented approvals/oversight. Retention governed by national law and supervisory expectations.
- **Automation opportunity:** Continuous control-testing evidence with repeatable scopes; automated mapping of pentest findings to Art. 21 measures; exportable audit packs (human + machine-readable) showing cadence, coverage, remediation SLAs, and sign-off.

## 3. DORA - Regulation (EU) 2022/2554

- **Official sources:** [EUR-Lex CELEX:32022R2554](https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX:32022R2554); [EBA - Digital Operational Resilience Act](https://www.eba.europa.eu/activities/single-rulebook/regulatory-activities/digital-operational-resilience-act)
- **Status/timeline (precise):** Entered into force **16 January 2023**. **Applicable from 17 January 2025**. Advanced testing (Arts. 26-27): **Threat-Led Penetration Testing (TLPT)** required for designated financial entities **at least every 3 years** (frequency adjustable by the TLPT authority per framework) using a TIBER-EU-aligned approach detailed in TLPT RTS (Commission Delegated Regulation (EU) 2025/1190).
- **Testing obligations:** Proportionate ICT testing programme (Arts. 24-25) including vulnerability assessments/scans, network security assessments, gap analyses, physical security reviews, source code reviews where feasible, scenario-based tests, and **penetration testing**. TLPT (Arts. 26-27) targets critical/live production systems supporting critical or important functions of designated entities.
- **Mandate vs incentive:** **Mandatory** for in-scope financial entities and relevant ICT third-party providers.
- **Artifacts/evidence expected:** ICT testing strategy/program and results; vulnerability and remediation tracking; TLPT scoping, threat intelligence, red-team and blue-team reports, remediation plans, test summary/attestation reports to authorities; evidence of follow-up and closure; tester qualification/independence evidence.
- **Format/attestation/retention:** Secure submissions and reporting to competent/TLPT authorities per RTS procedures; strong traceability, confidentiality, and retention for supervisory review. Formal attestation/summary and remediation validation are central to TLPT closure.
- **Automation opportunity:** Evidence-rich, repeatable non-TLPT penetration/vulnerability testing with reproducible HTTP traffic and full scoping; machine-readable findings for registers/remediation workflows; packaged artifacts to support TLPT preparation, scoping, and remediation verification (automation complements, not replaces, regulated TLPT).

## 4. SEC Cybersecurity Disclosure Rules - Regulation S-K Item 106; Form 8-K Item 1.05

- **Official sources:** [SEC Press Release 2023-139](https://www.sec.gov/newsroom/press-releases/2023-139); [Final Rule 33-11216](https://www.sec.gov/rules/final/2023/33-11216.pdf); [Fact Sheet](https://www.sec.gov/files/33-11216-fact-sheet.pdf)
- **Status/timeline (precise):** Adopted **26 July 2023**; effective **30 days after Federal Register publication**. **Form 10-K/20-F (Item 106):** for fiscal years ending on or after **15 December 2023**. **Form 8-K Item 1.05 / Form 6-K:** beginning the later of **90 days after Federal Register publication** or **18 December 2023**; **smaller reporting companies** receive an additional **180 days** for Form 8-K. Inline XBRL tagging begins **one year** after initial compliance with the related disclosure requirement. (U.S. Attorney General may authorize delayed 8-K disclosure for national security/public safety.)
- **Testing implications:** **No explicit mandate to conduct penetration tests.** Registrants must describe processes for assessing, identifying, and managing material cybersecurity risks and governance (Item 106). Robust testing and investigation evidence supports materiality determinations and accurate disclosures.
- **Mandate vs incentive:** **Mandatory disclosure regime** for registrants/FPIs; strong incentive to maintain demonstrable, defensible testing and risk-management evidence.
- **Artifacts/evidence expected:** Process/policy documentation; risk assessment and testing outputs (including pentest/assessment reports where used) supporting Item 106; incident timelines, scope/impact analyses, and board/management oversight records; contemporaneous investigation evidence substantiating 8-K determinations.
- **Format/attestation/retention:** EDGAR filings (8-K/10-K/20-F/6-K) with Inline XBRL per schedule; internal records must support disclosure controls and withstand SEC inquiry/litigation holds (retention driven by securities, audit, and legal-hold obligations rather than a single rule-stated year count).
- **Automation opportunity:** Preserve contemporaneous, tamper-evident technical evidence (e.g., HTTP traces tied to exploited paths) to accelerate materiality analysis and defensible narratives; maintain auditable testing cadence/coverage records backing Item 106 statements.

## 5. PCI DSS v4.x - Requirement 11.4 (Penetration Testing)

- **Official source:** [PCI SSC Document Library](https://www.pcisecuritystandards.org/document_library/) (PCI DSS v4.0.1, ROC/AOC templates, guidance)
- **Status/timeline (precise):** PCI DSS v4.0 published **31 March 2022**; v4.0 retired **31 December 2024**. **v4.0.1** is current. Future-dated requirements became **mandatory 31 March 2025**. Req. 11.4 applies on defined recurring and change-triggered cadences.
- **Testing obligations (mandated):** **11.4.1** defined methodology (industry-accepted), coverage of CDE/critical systems, internal/external and application/network layers, incorporation of threats/vulns from prior 12 months, retention of results and remediation activities. **11.4.2** external penetration testing at least **annually** and after any significant change/upgrade. **11.4.3** internal penetration testing at least **annually** and after significant change. **11.4.4** exploitable vulnerabilities/security weaknesses corrected and testing repeated to verify corrections. **11.4.5** segmentation controls tested at least **annually** and after changes (where segmentation used). **11.4.6** (service providers) segmentation controls tested at least **every six months** and after changes. **11.4.7** (multi-tenant service providers) support for external penetration testing by customers/third parties as applicable.
- **Artifacts/evidence expected:** Scope and methodology; rules of engagement/authorization; detailed findings with evidence; remediation records and **retest evidence**; segmentation test methodology/results; qualified tester credentials and independence; assessor-reviewed evidence in ROC and entity AOC attestations.
- **Format/attestation/retention:** Typically PDF/Word reports plus workpapers; assessed in ROC and attested in AOC. Organizations must retain evidence sufficient to demonstrate ongoing/periodic compliance and support assessor validation across assessment periods. Machine-readable exports not mandated but useful for GRC and assessor efficiency.
- **Automation opportunity:** Continuous/triggered scoped tests with reproducible HTTP evidence per finding, automated retest workflows, segmentation-change tracking, standardized machine-readable outputs mapped to 11.4.x, and signed evidence packages to streamline QSA validation.

## 6. ISO/IEC 27001:2022 (ISMS)

- **Official source:** [ISO/IEC 27001:2022](https://www.iso.org/standard/27001)
- **Status/timeline:** 2022 edition current; certification transition from 2013 completed across audit cycles.
- **Testing obligations:** **Risk-based, not prescriptively "pentest-mandated."** Requires ISMS operation, monitoring/measurement/evaluation, internal audit (9.2), and management review (9.3). Relevant Annex A controls commonly include **A.8.8 Management of technical vulnerabilities** and **A.8.29 Security testing in development and acceptance** (selected/justified in SoA).
- **Mandate vs incentive:** Certification **voluntary** unless contractually/regulatorily required; once in scope, surveillance/recertification audits **require evidence** of control effectiveness.
- **Artifacts/evidence expected:** ISMS scope, risk assessment/treatment, SoA, policies/procedures, vulnerability/patch records, test plans/results (including penetration tests if used), internal audit reports, corrective actions, management review minutes, competence records.
- **Format/attestation/retention:** Controlled documents/records per Clause 7.5 (format not prescribed). External attestation via accredited certification/audit. Retention defined by organization and legal/contractual needs.
- **Automation opportunity:** Map automated findings and HTTP evidence to Annex A controls/risk treatments; maintain time-stamped auditor-ready evidence; generate SoA-supporting effectiveness and remediation tracking reports.

## 7. SOC 2 (AICPA Trust Services Criteria)

- **Official source:** [AICPA Trust Services Criteria](https://www.aicpa-cima.com/resources/download/trust-services-criteria)
- **Status/timeline:** Ongoing attestation framework used broadly in 2025-2026 vendor assurance.
- **Testing expectations:** **No prescriptive mandate for penetration testing cadence/tooling.** Common criteria require risk assessment, monitoring, and vulnerability/incident detection and remediation (e.g., CC3/CC4/CC7). Penetration tests are commonly provided as operating-effectiveness evidence.
- **Mandate vs incentive:** **Market/contract-driven** (strongly incentivized), not a statute.
- **Artifacts/evidence expected:** System description, control matrix, policies, risk assessments, vulnerability scan/pentest reports, remediation tickets/retests, change management and logging/monitoring evidence, incident records; auditor samples evidence for Type II periods.
- **Format/attestation/retention:** CPA-issued SOC 2 Type I/II report (restricted) with management assertion and auditor opinion; underlying evidence retained per engagement and record-retention policies (often multi-year). Machine-readable bundles aid sampling and customer assurance.
- **Automation opportunity:** Continuously generated, auditor-friendly evidence packs (scoped tests, raw HTTP traces, timestamps, retest proof) mapped to TSC; reduce sample-prep effort and strengthen period-of-coverage assurance.

## 8. HIPAA Security Rule (45 CFR Part 164, Subpart C)

- **Official sources:** [HHS Security Rule overview](https://www.hhs.gov/hipaa/for-professionals/security/index.html); [45 CFR 164.308](https://www.ecfr.gov/current/title-45/subtitle-A/subchapter-C/part-164/subpart-C/section-164.308); [45 CFR 164.316](https://www.ecfr.gov/current/title-45/subtitle-A/subchapter-C/part-164/subpart-C/section-164.316)
- **Status/timeline:** Enforceable baseline rule in force; organizations must maintain ongoing compliance. (Proposed modernization efforts may evolve, but no finalized replacement supersedes the cited baseline as of this note.)
- **Testing obligations:** Requires **risk analysis** (164.308(a)(1)(ii)(A)), risk management, and **periodic technical and nontechnical evaluation** (164.308(a)(8)) in response to environmental/operational changes affecting ePHI security. **Penetration testing is not explicitly named**, but is a widely accepted evaluation/control-validation method.
- **Mandate vs incentive:** **Mandatory** for covered entities and business associates.
- **Artifacts/evidence expected:** Risk analysis and risk management documentation; evaluation reports; policies/procedures; audit logs/access reviews; vulnerability/patch and remediation records; incident/breach documentation; BAAs and contingency plans. Pentest/vuln assessment reports commonly retained as evaluation evidence.
- **Format/attestation/retention:** Documentation must be retained for **6 years** from creation or last effective date (164.316(b)(2)(i)) and made available to responsible workforce members and HHS/OCR upon request. No mandated file format; integrity/availability required.
- **Automation opportunity:** Repeatable evaluation artifacts with dated, reproducible technical evidence (HTTP traces, exploitability proof, retests) linked to risk items; streamline OCR responses and demonstrate ongoing evaluation after changes.

---

## Key takeaways for EyeOfG0d

1. **Strongest explicit pentest/testing mandates:** PCI DSS 11.4 (cadence/scope/segmentation/retest) and DORA (proportional testing + TLPT for designated entities).
2. **Mandatory regimes where testing substantiates compliance:** NIS2 (effectiveness testing/audit), CRA (technical documentation/vulnerability handling), SEC (defensible risk-management and incident processes), HIPAA (periodic evaluation/risk analysis support).
3. **Assurance frameworks where evidence quality drives outcomes:** ISO 27001 and SOC 2 depend on auditable proof of control effectiveness; traceable artifacts reduce audit friction.
4. **Product wedge:** Automated, signed, human+machine-readable evidence bundles with **real HTTP traffic per finding**, retest linkage, scope/change tracking, and policy-driven retention directly address the compliance-grade evidence gap.
