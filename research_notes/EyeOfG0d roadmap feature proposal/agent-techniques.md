# SOTA LLM-Based Offensive-Security Agent Techniques (2024–2026)
*Compiled: 2026-11-19 | For: EyeOfG0d roadmap feature proposal*

## Scope & method
- Focus: agent techniques relevant to offensive security (CTF, pentest, vuln exploitation) with 2024–2026 evidence.
- Evidence sources: arXiv papers, benchmark papers, and major OSS repos (PentestGPT, Strix, CAI, HexStrike). `websearch` unavailable in-session; XBOW validation blog URL returned 404; HTB/picoCTF agent-specific 2026 leaderboard numbers not concretely sourced beyond general benchmark context.

## 1) Benchmark evidence (quantitative)

| Benchmark / study | What it measures | Key numbers (reported) | Notes |
|---|---|---:|---|
| [Cybench (arXiv:2408.08926)](https://arxiv.org/abs/2408.08926), ICLR 2025 Oral | 40 pro-level CTF tasks + subtasks; 8 models, 4 scaffolds | Top models (GPT-4o, Claude 3.5 Sonnet, o1-preview, Claude 3 Opus) solved tasks humans did in **≤11 min unguided**; hardest task (human **24h54m**) unsolved | Highlights scaffold sensitivity and gap on hard tasks; code/data: https://cybench.github.io |
| [AutoPenBench (arXiv:2410.03225)](https://arxiv.org/abs/2410.03225) | 33 pentest tasks (in-vitro + real-world), milestone scoring | Fully autonomous agent **21% SR** (27% simple, 1 real-world); semi-autonomous/human-assisted **64% SR** | Human-in-loop and scaffolding materially improve outcomes; repo: https://github.com/lucagioacchini/auto-pen-bench |
| [NYU CTF Bench (arXiv:2406.05590)](https://arxiv.org/abs/2406.05590) | Scalable OSS CTF benchmark + automated framework | Dataset/framework for evaluating LLMs on CTFs across categories (5 LLMs evaluated in paper) | Foundation for EnIGMA/other agent evals; https://github.com/NYU-LLM-CTF/NYU_CTF_Bench |
| [EnIGMA (arXiv:2409.16165)](https://arxiv.org/abs/2409.16165), ICML 2025 | SWE-agent-derived CTF agent with interactive tools | **SOTA on NYU CTF, InterCode-CTF, and CyBench** (390 challenges, 4 benchmarks) via interactive debugger/server tools; introduces "soliloquizing" (hallucinated observations) | Execution-grounded interactive tooling is a key differentiator; https://enigma-agent.com |
| [Hacking CTFs with Plain Agents (arXiv:2412.02776)](https://arxiv.org/abs/2412.02776) | Minimal agent on InterCode-CTF | **95% on InterCode-CTF** with ReAct+Plan prompting, tool use, multiple attempts (vs 29% Phuong et al. 2024, 72% Abramovich et al. 2024) | Suggests strong elicitation/retry can rival complex scaffolds on easier CTF benchmarks |
| [LLM Agents can Autonomously Exploit One-day Vulnerabilities (arXiv:2404.08144)](https://arxiv.org/abs/2404.08144) | 15 real-world one-day vulns (incl. critical CVEs) | **GPT-4 exploited 87% with CVE description** vs **0%** for GPT-3.5/open LLMs/ZAP/Metasploit; **7% without description** | Knowledge/context (advisory/CVE text) is decisive for exploit success |
| [CAIBench (arXiv:2510.24317)](https://arxiv.org/abs/2510.24317) | Meta-benchmark: Jeopardy/A&D CTFs, cyber ranges, knowledge, privacy, robotics (10k+ instances) | Knowledge ~**70%** but A&D **20–40%**, robotics **22%**; scaffold+model match yields up to **2.6× variance** in A&D | Capability gap: conceptual knowledge ≠ adaptive multi-step attack/defense; framework fit matters |
| [G-CTR (arXiv:2601.05887)](https://arxiv.org/abs/2601.05887) | Game-theoretic guidance layer over agent loop (attack graphs + Nash equilibrium digest) | 44-run cyber-range: success **20.0%→42.9%**, cost/success **÷2.7**, behavioral variance **÷5.2**; in A&D "Purple" agent wins ~**2:1** vs LLM-only baseline | Strategic digest/grounding can cut search space and improve reliability/cost |

## 2) Multi-agent orchestration patterns

| Pattern | Evidence/examples | Tradeoffs / when to use |
|---|---|---|
| **Planner–reasoner / worker–executor (hierarchical-ish)** | [PentestGPT](https://github.com/GreyDGL/PentestGPT) (USENIX Security 2024 lineage): reasoning/generation/parsing sessions + Pentesting Task Tree (PTT) in legacy interactive mode; v1.0 adds staged pipelines (CTF: recon→exploit→walkthrough; pentest: asset discovery→vuln ID→report) | Strong for long-horizon decomposition and state tracking; risk of stale plan without tight feedback loops |
| **Multi-agent swarms / specialized roles** | [Strix](https://github.com/usestrix/strix): autonomous AI "hackers"/multi-agent orchestration, dynamic runtime validation, PoC-oriented findings; [CAI (arXiv:2504.06017)](https://arxiv.org/abs/2504.06017): modular agents + HITL, bug-bounty-ready workflows (repo archived Aug 2026) | Good for parallel recon/exploit/validation; coordination overhead and higher token/tool cost |
| **Tool-mediated "MCP hub" orchestration** | [HexStrike AI](https://github.com/0x4m4/hexstrike-ai): MCP server bridging agents (Claude/GPT/Copilot etc.) to 150+ security tools, autonomous agents for vuln/intel/exploit chains | Fast tool leverage and ecosystem integration; vendor/marketing performance claims should be validated independently |
| **Strategic guidance layer over base agent** | [G-CTR](https://arxiv.org/abs/2601.05887): extracts attack graph, computes equilibria, injects concise digest into loop | Improves focus/consistency without replacing executor; depends on quality of extracted state/graph |
| **Minimal/plain agent** | [Plain Agents](https://arxiv.org/abs/2412.02776): ReAct+Plan + retries + tools, minimal harness | Low complexity, strong on simpler benchmarks; may underperform on complex, long, or adaptive environments (cf. Cybench hard tasks, CAIBench A&D gap) |

## 3) Memory & knowledge architectures
- **Externalized task state / structured plan memory**: PTT/task trees (PentestGPT) and stage handoff artifacts reduce context loss over long engagements.
- **Environment-grounded memory**: logs, command outputs, artifacts, and discovered assets/services as the source of truth (common across PentestGPT/Strix/CAI/Cybench-style agents).
- **Retrieved/advisory knowledge**: providing vulnerability descriptions (CVE/advisory) dramatically boosts exploit success (87% vs 7% in [arXiv:2404.08144](https://arxiv.org/abs/2404.08144)); implies strong value from vuln DB/RAG injection at decision points.
- **Condensed strategic memory/digests**: G-CTR-style attack-graph digest compresses situation into actionable guidance, reducing ambiguity/hallucination and variance ([arXiv:2601.05887](https://arxiv.org/abs/2601.05887)).
- **Interactive session memory with guardrails**: EnIGMA adds specialized interfaces but also exposes failure mode *soliloquizing* (hallucinated observations) — memory must be tied to verifiable tool/environment traces ([arXiv:2409.16165](https://arxiv.org/abs/2409.16165)).

## 4) Self-improvement loops
- **Retry / multi-attempt sampling**: Plain Agents achieve 95% on InterCode-CTF with multiple attempts and simple prompting ([arXiv:2412.02776](https://arxiv.org/abs/2412.02776)); cheap but increases cost/latency.
- **Feedback-from-execution loops**: observe tool/target response → revise plan/payload (core to ReAct-style pentest agents; EnIGMA/Cybench scaffolds).
- **Human-in-the-loop correction**: AutoPenBench shows assisted mode 64% SR vs 21% autonomous, indicating HITL is a high-leverage "improvement" mechanism ([arXiv:2410.03225](https://arxiv.org/abs/2410.03225)).
- **Guidance distillation (online)**: G-CTR recomputes/feeds strategic digest each loop to stabilize behavior and improve success/cost ([arXiv:2601.05887](https://arxiv.org/abs/2601.05887)).
- **Open/research gap**: limited standardized evidence in fetched sources for durable cross-run learning (fine-tuning/skill library evolution) in offensive agents; treat claims cautiously and measure.

## 5) Execution grounding (vision/browser/computer-use/MCP/tools)
- **Shell + security toolchains**: canonical grounding in CTF/pentest benches (Cybench, AutoPenBench, NYU CTF, CAI/Strix/PentestGPT/HexStrike) — agents must run commands, parse outputs, iterate.
- **Interactive terminal interfaces**: EnIGMA's interactive agent tools (debugger, server connection utilities) materially improved SOTA on NYU CTF/InterCode-CTF/CyBench ([arXiv:2409.16165](https://arxiv.org/abs/2409.16165)).
- **Browser/runtime validation**: Strix emphasizes dynamic code execution and PoC validation in sandboxed environments (repo/docs claims); browser automation is increasingly standard for web-app attack paths.
- **MCP / tool protocol bridges**: HexStrike exposes 150+ tools via MCP to multiple client agents; MCP useful for decoupling agent reasoning from tool execution and for enterprise integration (validate vendor performance claims).
- **Computer-use/vision**: not directly quantified in the fetched offensive-security benchmarks above; relevant where GUI-only targets exist, but shell/API/browser grounding currently has stronger measured evidence in this domain.

## 6) Cost/latency techniques (evidence-backed + applicable)
- **Strategic search-space reduction**: G-CTR cut **cost/success by 2.7×** and variance by 5.2× while raising success (20.0%→42.9%) by guiding actions ([arXiv:2601.05887](https://arxiv.org/abs/2601.05887)).
- **Scaffold/model right-sizing**: CAIBench shows **up to 2.6×** A&D variance from scaffold+model match ([arXiv:2510.24317](https://arxiv.org/abs/2510.24317)); route easy steps to cheaper/faster models, reserve strong models for planning/exploit synthesis.
- **Minimal harness + bounded retries**: Plain-agent results suggest avoiding unnecessary orchestration overhead on simpler tasks ([arXiv:2412.02776](https://arxiv.org/abs/2412.02776)); cap attempts/tools by task class.
- **Context/KV efficiency (general serving techniques, apply to agents)**: prompt/context caching, prefix reuse, KV-cache compression/eviction, and concise state digests reduce repeated long-context costs — especially important for multi-turn tool traces; pair with G-CTR-like digests to keep prompts short.
- **Early-stop & milestone gating**: use benchmark-style milestones (AutoPenBench) to halt unproductive branches and replan quickly.

## 7) EyeOfG0d roadmap recommendations (evidence-informed)
1. **Hybrid orchestration**: staged planner/executor + optional specialist agents; add strategic digest/attack-graph guidance for hard targets (G-CTR evidence).
2. **Execution-first grounding**: invest in reliable shell/browser/debugger/MCP tool interfaces and trace logging; require evidence/PoC before success (Strix/EnIGMA direction).
3. **State & knowledge layer**: persistent task tree + artifact store + vuln/advisory retrieval (CVE context high impact per one-day study).
4. **Eval-driven development**: track on Cybench/AutoPenBench/NYU-CTF-like tasks; report SR, time/cost per success, variance, assisted vs autonomous (CAIBench shows large scaffold/model effects).
5. **Cost controls**: model routing, prompt caching/KV reuse, context digests, bounded retries, and milestone-based early stopping.
6. **Safety/ops**: HITL gates for destructive/high-risk actions (assisted mode lifts SR), auditability, and explicit handling of hallucinated observations ("soliloquizing").

## Sources
- Zhang et al., *Cybench: A Framework for Evaluating Cybersecurity Capabilities and Risks of Language Models*, arXiv:2408.08926 (2024/2025). https://arxiv.org/abs/2408.08926
- Gioacchini et al., *AutoPenBench: Benchmarking Generative Agents for Penetration Testing*, arXiv:2410.03225 (2024). https://arxiv.org/abs/2410.03225
- Shao et al., *NYU CTF Bench*, arXiv:2406.05590 (2024/2025). https://arxiv.org/abs/2406.05590
- Abramovich et al., *EnIGMA*, arXiv:2409.16165 (2024/2025). https://arxiv.org/abs/2409.16165
- Turtayev et al., *Hacking CTFs with Plain Agents*, arXiv:2412.02776 (2024). https://arxiv.org/abs/2412.02776
- Fang et al., *LLM Agents can Autonomously Exploit One-day Vulnerabilities*, arXiv:2404.08144 (2024). https://arxiv.org/abs/2404.08144
- Mayoral-Vilches et al., *CAI: An Open, Bug Bounty-Ready Cybersecurity AI*, arXiv:2504.06017 (2025). https://arxiv.org/abs/2504.06017
- Sanz-Gómez et al., *CAIBench*, arXiv:2510.24317 (2025). https://arxiv.org/abs/2510.24317
- Mayoral-Vilches et al., *Cybersecurity AI: A Game-Theoretic AI for Guiding Attack and Defense (G-CTR)*, arXiv:2601.05887 (2026). https://arxiv.org/abs/2601.05887
- Repos: PentestGPT https://github.com/GreyDGL/PentestGPT | Strix https://github.com/usestrix/strix | CAI (archived) https://github.com/aliasrobotics/cai | HexStrike AI https://github.com/0x4m4/hexstrike-ai
- Note: XBOW validation blog (https://xbow.com/blog/xbow-validation-benchmarks) returned 404 during collection.
