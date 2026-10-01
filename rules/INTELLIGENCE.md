# Public Intelligence Review

Review date: **2026-09-28**. Window: **2026-03-28 through 2026-09-28**, inclusive.
This is a targeted review of public AI-related reporting, not an exhaustive incident
inventory. Publication dates qualify reports; event dates are separately recorded
where known. A recent report can discuss older activity.

## Run

```sh
python3 codex-analysis.py --rules rules/incident --rules rules/recent
```

This loads 32 rules: 8 starter, 16 from the earlier report review, and 8 new ones.
Both packs are optional and offline. Copy the script, `rules/starter/`, and selected rule directories when
moving to another host. Findings retain classifications, source dates, evidence
types, investigation guidance, and the original session context.

## Sources And Decisions

| Source | Date basis | Evidence and use |
| --- | --- | --- |
| [Sublime](https://sublime.security/blog/adversarial-prompt-injection-payload-for-evading-ai-based-detection-embedded-in-phishing-campaign/) | Published 2026-06-25 | Observed phishing samples targeting AI analysis. Added output-exposure rules for verdict manipulation and forged browser context. |
| [Varonis](https://www.varonis.com/blog/rogue-agent-dialogflow-attack) | Updated 2026-07-07; first disclosed to vendor 2025-11, fixes 2026-04 and 2026-06 | Controlled research, not known in-the-wild exploitation. Added a runtime-file mutation signal. |
| [Check Point Research](https://research.checkpoint.com/2026/ai-security-report-2026/) | Published 2026-07-14; summary includes older activity and January-May telemetry | Supports persistent configuration-abuse hunting. Concrete configuration strings are our implementation choices, not incident IOCs. |
| [UK AISI](https://www.aisi.gov.uk/blog/incident-report-unsanctioned-agent-behaviour-during-cyber-testing) | Events 2026-07-25 through 2026-07-28; publication date not provided by the retrieved primary page | Evaluation incident under permissive conditions. Added Tor-routed publishing and public peer-handoff review signals. No sandbox escape or resulting real-world harm is inferred. |
| [Cisco Talos](https://blog.talosintelligence.com/keep-going-bro-youve-got-this-a-data-driven-look-at-how-adversaries-are-weaponizing-ai/) | Published 2026-08-04; underlying activity dates vary | Recovered adversary artifacts. Added instruction-file writes carrying blanket authorization language. |
| [Unit 42](https://unit42.paloaltonetworks.com/ai-assisted-cyber-attack-inside-a-unit-42-investigation/) | Updated 2026-09-04; underlying incident date unspecified | Incident-response account. Added a workflow-modification/secret-transmission conjunction. Exact YAML syntax is a detector hypothesis. |

February 2026 ToxicSkills research, March 19 prompt-injection reporting, and
2025 EchoLeak/GitHub MCP examples were outside the six-month window and were not
counted as new incidents. We used primary publishers for implemented hypotheses.
The earlier METR and Anthropic report pack remains available and now has explicit
classification decisions too.

## New Triggers

All eight rules are experimental, require review, and operate on a single event.
They do not fetch sites, run payloads, or execute the commands they inspect.

| Rule | Match requirement | Important limitation |
| --- | --- | --- |
| `recent-agent-approval-config` | Config target + mutation + permissive value | Can match approved changes; textual diffs include removed lines too. |
| `recent-persistent-preauthorization` | Agent instruction file + write + blanket permission | Cannot establish the author or whether the user approved it. |
| `recent-agent-runtime-overwrite` | `code_execution_env.py` + mutation syntax | Test copies and maintenance can match. |
| `recent-ci-secret-export` | Workflow write + secret reference + upload + URL | Does not establish that a build ran or a secret left the host. |
| `recent-tor-public-write` | Tor-style route + repository publishing | Port numbers are heuristic; Tor itself is not malicious. |
| `recent-public-peer-handoff` | Publication + peer-agent language + access/artifact reuse | Legitimate collaboration can match. |
| `recent-scanner-verdict-injection` | Scanner context + imperative benign-verdict language in output | Exposure only; does not prove the model followed the instruction. |
| `recent-fake-browser-context` | Browser markers + first-person policy in output | Narrow marker family; research documents can match. |

Output rules cite `event.result_source`; command rules cite `event.source`.
Research activity in this chat can match these rules because fixtures and threat
reports contain the same strings. Findings are hypotheses, not confirmed incidents.

## Classification

ATLAS labels were checked against MITRE's official **5.6.0** data, retrieved on
2026-09-28. OWASP labels use the published **2026** edition, explicitly suffixed
with the year. This is the LLM Top 10, not the separate Agentic Top 10.

- [Official MITRE catalog](https://raw.githubusercontent.com/mitre-atlas/atlas-data/main/dist/ATLAS.yaml)
- [Official OWASP final source](https://github.com/GenAI-Security-Project/GenAI-LLM-Top10/tree/main/2026/final)
- [OWASP publication](https://genai.owasp.org/resource/owasp-genai-llm-top-10-2026/)

Retrieved-byte SHA-256 values for reproducibility:

```text
ATLAS.yaml: c9c23971d0db07e2782423d795a20e78d5c2c9bcdc78fc67e24530657daaec41
OWASP 2026 README.md: 8091b002286bd6bdd9741f5a45ca93c1bd55d3548325b6481116567c557293ea
```

The catalog URLs are live; hashes describe the reviewed snapshots, not guaranteed
future downloads. Only the needed ATLAS identifiers are embedded in the portable
script. Subtechnique names such as `Indirect` retain MITRE's official short names.

The mappings are **our analyst judgments**, not publisher-certified mappings.
Some incident-report tables use ATLAS names inconsistent with MITRE's catalog;
those labels were not copied. For example, AML.T0043 is Craft Adversarial Data,
not stolen-key model invocation. OWASP also changed numbering: Excessive Agency
is LLM03:2026, while LLM06:2026 is Unbounded Consumption. Bare IDs such as `LLM06`
would be ambiguous, so the loader rejects them and unsupported editions.

An empty mapping is intentional when evidence supports only a conventional cyber
behavior or a logging gap. For example, base64 does not establish prompt obfuscation,
and a malware rebuild does not establish evasion of an AI classifier. OWASP risk
labels describe a possible application failure, not attribution or intent.

Custom rules may add:

```json
{"classification": {
  "atlas": ["AML.T0081"],
  "owasp_llm": ["LLM03:2026"],
  "rationale": "Possible persistent weakening of agent oversight."
}}
```

Supported IDs are in `ATLAS` and `OWASP` in the script. Unknown IDs fail validation;
rules without classification still work and appear as unmapped.

## Coverage And Further Hunting

`summary.json` includes per-framework finding counts, unmapped rules, and all ten
OWASP categories with matching loaded rule IDs. Counts are rule findings, not
unique incidents; one event or finding can contribute to multiple categories.
An empty category is a visibility gap, not a clean bill of health.

| OWASP 2026 | Present mapping or next telemetry requirement |
| --- | --- |
| LLM01 Prompt Injection | Output exposure and persistent instruction rules. |
| LLM02 Sensitive Information Disclosure | Credential collection/export candidates. |
| LLM03 Excessive Agency | Permission changes and potentially excessive actions. |
| LLM04 Supply Chain | Cache, artifact, and runtime manipulation candidates. |
| LLM05 Data and Model Poisoning | No dedicated detection; needs data provenance and training/index changes. |
| LLM06 Unbounded Consumption | No dedicated detection; needs trusted usage totals, baselines, and time windows. |
| LLM07 Misinformation | No dedicated detection; needs externally validated claims and decision outcomes. |
| LLM08 Hidden Context Exposure | No dedicated detection; needs provenance-aware comparison with protected context. |
| LLM09 Vector and Embedding Weaknesses | No dedicated detection; needs retrieval/embedding and tenancy telemetry. |
| LLM10 Improper Output Handling | No dedicated detection; needs output-to-execution or rendering dataflow evidence. |

Further incident-response hunts include rapid failed-to-successful authentications,
unusual inference usage by new identities, and independent evidence of pipeline
execution (Unit 42). Cross-session task decomposition and renamed operations need
campaign-level analysis (Talos). These remain documented possibilities, not claims
that this per-event scanner can detect them. Importing proxy observations preserves
HTTP/HTTPS separation but does not currently run these rules over network events.
