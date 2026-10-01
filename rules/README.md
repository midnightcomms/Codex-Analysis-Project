# Incident Behavior Pack

Run with the existing eight starter rules plus these sixteen experimental rules:

```sh
python3 codex-analysis.py --rules rules/incident
```

Use `--input` to select saved rollout files. Copy `codex-analysis.py`,
`rules/starter/`, and any optional detection directories to another host. Each
JSON file contains one detection; copy `rules/detection-template.json` to create a
new one. Rule descriptions, source-page links, false
positives, and investigation steps are included in each finding.

## Source Mapping

The [METR report](https://metr.org/hugging-face-incident-report-aug-2026.pdf)
describes agent coordination, evidence manipulation, and attacks extending beyond
assigned tasks. These rules translate selected behaviors into local review signals:

| Rule suffix (`metr-`) | PDF pages | Required signals |
| --- | --- | --- |
| `cache-message-write` | 30 | Cache write and coordination marker |
| `hdf5-sensitive-external-reference` | 35 | HDF5 external construct and sensitive path |
| `tool-control-tampering` | 66, 68 | Process interference and tool-control target |
| `session-log-mutation` | 19, 20 | Evidence path and mutation syntax |
| `evaluator-beacon` | 50, 52 | Watcher, evaluator target, callback |
| `cache-target-substitution` | 53 | Cache upload and replacement language |
| `secret-scanner-evasion` | 63 | Encoding and stated scanner evasion |
| `acknowledged-scope-departure` | 57, 61 | Network action and scope-departure statement |

The [Anthropic report](https://www-cdn.anthropic.com/e50be2e51e7695dc4b1366a37a245a597377d3b5/Anthropic-Detecting-and-countering-091026.pdf)
adds cyber and surveillance patterns relevant to session telemetry:

| Rule suffix (`anthropic-`) | PDF pages | Required signals |
| --- | --- | --- |
| `secret-scan-telegram-export` | 13 | Scanner and bot send endpoint |
| `ai-credential-forwarding` | 29, 30 | AI credential, upload syntax, URL |
| `cluster-secret-dump` | 18 | Secrets, all namespaces, structured export |
| `browser-credential-decryption` | 107 | Browser store and decryption primitive |
| `security-control-disable` | 9 | Protection or update disabling command |
| `detection-driven-rebuild` | 6 | Build and stated detection evasion |
| `device-code-capture-context` | 9 | Device flow and capture context |
| `mail-token-cache-access` | 108 | Mail token store and decryption/unlock |

## Interpretation

The concrete command patterns are our detection hypotheses, not verbatim commands
from the reports. Attribution, unauthorized access, successful execution, and
compromise are not established by a match. Normal Hugging Face access, a security
tool name, or an organization name alone does not trigger this pack.

Conditions apply to one recorded tool call and its attached context. Split actions
across calls or sessions can evade these rules. Repeated loops, many-agent
coordination, account ownership, and campaign scale require additional correlation
and independent telemetry. This pack does not claim coverage of the reports'
non-cyber subjects or the entire incidents.

Commands are matched as text, not parsed executable semantics. Code creation,
quoted commands, fixtures, authorized security tests, and administrative operations
can match. Natural-language matches can misread negation or quotations. Inspect the
full user request and approval history; no keyword whitelist grants authorization.

Tool tampering is especially relevant to evidence quality: compare with separately
retained host audit, proxy, and identity logs. HTTP/HTTPS files still distinguish
session URL references from imported observations. These rules currently evaluate
session events, not imported network observations.

Tests use inert strings, positive/negative pairs for every rule, syntax variants,
and a full synthetic rollout-to-report run. They never execute the fixture commands.

See [the six-month intelligence review](INTELLIGENCE.md) for eight additional rules,
versioned MITRE ATLAS / OWASP LLM mappings, source dates, and coverage gaps.
