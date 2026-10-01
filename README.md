# AI session analysis for Codex by Codex

An offline detection prototype for Codex session logs. It adds recorded task
context to command and output detections, with separate HTTP and HTTPS logs.
Detections use a limited declarative rule format with one file per detection.

## Run Once

Requires Python 3.9 or newer on Linux, macOS, or Windows. Copy `codex-analysis.py`
and `rules/starter/` together to the host, then run it as the user whose Codex
sessions you want to inspect:

```sh
python3 codex-analysis.py
```

On Windows use `py -3 codex-analysis.py`. No API key, administrator access, network
connection, installed Codex executable, or pip packages are required. Python
must be installed. Default discovery scans `$CODEX_HOME/sessions` and
`$CODEX_HOME/archived_sessions`, falling back to `~/.codex`. It scans accessible
plain JSONL files; it does not collect other users' sessions or remote hosts.

```sh
python3 codex-analysis.py --input /path/to/sessions --output ./triage-report
python3 codex-analysis.py --match suspicious.example --match "private_key"
python3 codex-analysis.py --input examples/session.jsonl --rules examples/context-rule.json --network-log examples/network.jsonl --output ./demo-report
```

`--input`, `--rules`, `--match`, and `--network-log` can each be repeated. The output directory
must not exist; reports are never overwritten. By default each run gets a new
timestamped directory under `~/codex-analysis-reports`, outside the source tree.
Choose an external destination with `--output` when packaging or sharing this
project. Exit code 0 means the scan completed, including when it
found detections; 2 means a configuration error or partial coverage. Inspect
`summary.json` for diagnostics. A clean scan does not establish that a session is safe.
The startup banner prints to stderr; the final result is indented JSON on stdout.

## Reports

| File | Contents |
| --- | --- |
| `findings.jsonl` | Rule, severity, matching selections, false positives, and enriched event |
| `events.jsonl` | All supported tool calls, including calls without detections |
| `http.jsonl` | HTTP URL references and imported HTTP observations |
| `https.jsonl` | HTTPS URL references and imported HTTPS observations |
| `summary.json` | Counts, file-change candidates, per-session timelines, per-file hashes and timestamps, limitations, and input/coverage errors |
| `report.html` | Offline session timelines, file-change inventory, MITRE ATLAS heatmap, file integrity and timing, detection evidence, and unique domain/URL inventory |

Each session has an **Activity Timeline** of supported tool calls ordered by the
recorded UTC timestamp. Rows mark detection matches, candidate file writes, and
HTTP/HTTPS references or imported observations associated with that call. Expand a
row for the recorded request, assistant statement, destinations, and links to
finding evidence. The same entries are in `sessions[].timeline` in `summary.json`.
Rows without valid timestamps appear last. Network items inherit the tool-call
position; their placement does not establish when a request occurred.

The **MITRE ATLAS Heatmap** displays the 15 techniques supported by this analyzer and how many
findings were mapped to each. It also shows the number of techniques with at least
one finding and the total technique matches. Darker cells indicate higher counts
within that report. Select a flagged cell to see links to its findings. A finding
can map to more than one technique; mappings are candidate classifications. The
grid is not the full ATLAS matrix.

The **Unique Domains and URLs** section groups all HTTP(S) destinations by host
(including subdomains and IP addresses), with separate reference and observation
counts. Expand a URL to see each associated session/call ID, action, user prompt,
assistant statement, justification, and evidence locations. These are recorded
associations, not proof of why a request occurred. Unmatched or ambiguous imported
observations have no attributed context. URLs mentioned in output or prompts are
not claimed to have been contacted. Credentials and query values are redacted and
fragments removed before grouping; distinct raw URLs can therefore merge. Context
excerpts are capped at 3,000 characters. The same inventory is available under
`network_inventory` in `summary.json`.

Every run generates `report.html`; open it directly in a browser. It lists distinct
session IDs (including sessions without tool calls), computer and user names, operations, file-write
indicators, HTTP/HTTPS reference and observation counts, and each session's
detections. Flagged sessions sort first. `summary.json` also contains the per-session
data under `sessions` and global session totals under `counts`.

Computer and user names are taken from explicit rollout `session_meta` fields
when available. Standard rollouts may not include them. When scanning the default
local Codex store, missing names identify the computer and account running this
analysis; the report labels that source `local_codex_store`. This is a local-file
association, not independent proof of a session's original host or actor.
Imported `--input` files without explicit identity fields show `Unknown`; working
directory paths and opaque account IDs are not treated as usernames. Conflicting
metadata for a grouped session also shows `Unknown` with a conflict label.

The **Session Files** table shows each JSONL file's SHA-1 hash, filesystem created
and modified timestamps, first and last valid record timestamps, and elapsed
session length. Its data is under `session_files` in `summary.json`. SHA-1 covers
the bytes present at the file size captured when scanning began, including
unrecognized or malformed records. Timestamps are shown in UTC. Session length is
the span between the earliest and latest valid record timestamps, not active time.
Creation time is shown as unavailable if the operating system or filesystem does
not expose it. On Linux, the script uses the system `stat` command when present.

The **File Changes** section lists recorded target paths under Created, Modified,
Deleted, and Create or modify. Each row links to its session call and shows the
working directory and extraction basis. The same entries are in `file_inventory`
in `summary.json`. Patch add/update/delete declarations and a subset of explicit
shell and Python file operations are recognized. Create or modify is used when a
command could either create or overwrite a path. Write-indicator calls without an
extractable path are listed separately under Unresolved write targets and in
`unresolved_file_calls`. These are **candidate operations**, not a filesystem
audit: denied or failed calls, quoted code, dynamic paths, nested scripts, and
unlogged operations limit accuracy. Shell targets can also be directories.

Operations are supported tool-call records, including calls denied or lacking a
result. File-write indicators count **calls containing write syntax**, not files
changed or confirmed successful writes. Patch calls touching multiple files count
once. Other writes (for example, a script whose source is not in the log) can be
missed; quoted code can produce false positives. Each event includes the indicator
reasons under `file_write`.

Sessions sharing an ID across files are grouped; repeated records in multiple files
are still counted. Missing IDs use the source path and are labeled `file_fallback`.
Unreadable or wholly invalid files do not establish a session and are diagnosed.
Network references remain distinct from imported observations. Imported traffic is
counted against a session only with an exact, unique session/call match; other
traffic appears in a separate unattributed total. Network items are not a count of
unique requests or bytes transferred.

HTML contains no JavaScript or remote assets, escapes untrusted evidence, and uses
the same redaction as the JSON logs. Finding command/context/output excerpts are
capped at 3,000 characters per field; full records remain in `findings.jsonl`.
No web server is required. Reports can still contain sensitive data; do not
include generated report folders when sharing the code.

Each event retains the preceding user request, latest non-analysis assistant
statement, explicit tool justification, working directory, requested sandbox
permission, and any result joined by call ID. Each context statement includes
its own source line and SHA-256 of the raw source line. A new user request clears
the prior assistant statement. Compaction and recorded task completion clear
context to avoid carrying an old request across an unknown boundary. Files are
processed independently; there is no inferred parent/fork context.

These are recorded statements, not verified intent or approval. Tool calls can
be denied or fail; a result does not establish success. Context never suppresses
the starter detections. Use it to investigate why an action was proposed and
whether it is consistent with the request. This tool does not recover hidden
reasoning or ask an LLM to invent an explanation.

## HTTP And HTTPS Evidence

Session URL references have `evidence_type=session_url_reference` and
`traffic_confirmed=false`. A URL in a command, prompt, or output does **not** prove
a request happened. There is no retrospective packet capture or TLS decryption.
Commands without explicit URLs, redirects, constructed URLs, and background
requests can be missed. Repeated references across events are retained.

To include observed traffic, export proxy, browser, or EDR observations into a
normalized JSONL file and pass `--network-log`. Each line must have an absolute
HTTP(S) `url`; optional fields are `timestamp`, `method`, `status`, `session_id`,
and `call_id`. No raw HAR/PCAP/vendor format parser is included. Example:

```json
{"timestamp":"2026-09-28T12:00:03Z","url":"https://example.test/api","method":"GET","status":200,"session_id":"session-123","call_id":"call-123"}
```

Imported observations are labeled `imported_network_observation` and
`traffic_confirmed=reported_by_input_log`: their accuracy depends on the supplied
log. Context is attached only on an exact, unique session ID and call ID match.
Other observations remain unattributed; matching a hostname is not enough.
The example network file is synthetic, not evidence that the example command ran.

## Rules

Eight default files in `rules/starter/` cover remote scripts piped to interpreters, credential
paths, uploads, destructive commands, encoded commands, escalation requests,
instruction override language in tool output, and missing user context.
They are starting points for tuning, not exhaustive threat coverage. Quoted
commands, documentation, test fixtures, and legitimate maintenance can match.

Copy [the detection template](rules/detection-template.json) to a new JSON file,
give it a unique `id`, and replace the example selection, context, investigation,
and classification. Each file must contain exactly one detection object. Pass a
file or a directory of detection files with `--rules`; directories are scanned
nonrecursively in filename order. JSON is portable; YAML requires PyYAML and
one document per file. See `examples/context-rule.json` for a rule matching a
command **and** its request.

The [incident behavior pack](rules/README.md) adds 16 experimental detections derived
from the METR Hugging Face and Anthropic September 2026 reports:

```sh
python3 codex-analysis.py --rules rules/incident
```

Findings include source-page references and investigation steps. The pack is
explicitly selected with `--rules`; the default remains eight rules.

The [six-month intelligence review](rules/INTELLIGENCE.md) adds eight more triggers
and documents MITRE ATLAS 5.6.0 / OWASP LLM Top 10 2026 classifications:

```sh
python3 codex-analysis.py --rules rules/incident --rules rules/recent
```

This selects 32 rules in total. Findings include candidate classifications and
their rationale; `summary.json` lists category counts, unmapped rules, and coverage
gaps across all ten OWASP risks. Mappings do not establish compromise or intent.

The optional [domain intelligence pack](rules/DOMAIN-INTELLIGENCE.md) adds five
precise URL/host indicators from a July 2026 FakeAgent investigation:

```sh
python3 codex-analysis.py --rules rules/domain-intelligence
```

It includes the reported redirect and backup domains, installer and public
Artifact URLs, and a C2 IP. These are historical indicators, not a verdict on
the current owner of a destination. General `claude.ai` traffic is not flagged.

Supported subset:

- Logsource exactly `{"product":"codex","category":"ai_session"}`.
- Field maps: AND between fields, OR between values; `|all` requires all values.
- Fields: `EventType`, `CommandLine`, `ToolName`, `UserRequest`, `AssistantContext`,
  `Justification`, `Output`, `Cwd`, `SandboxPermissions`, `ContextMissing`,
  `CommandDomains`, `CommandURLs`, `OutputDomains`, `OutputURLs`,
  `ObservedDomains`, `ObservedURLs`.
- URL/domain fields are arrays extracted from HTTP(S) URLs. `Command*` means a
  URL appears in a tool input, not that traffic occurred; `Output*` means it
  appears in the returned text. `Observed*` is populated only from an imported
  network record with a unique exact session ID and call ID match. Bare hostnames
  without a scheme are not extracted. Hosts are normalized to lowercase;
  URL queries are replaced by `REDACTED` and fragments removed before matching.
- Text equality with `*` and `?` wildcards, `contains`, `startswith`, `endswith`,
  and Python `re`. Text is case insensitive except regex (use `(?i)` explicitly).
- Conditions: selection names, `and`, `or`, `not`, parentheses, `1 of pattern`,
  `all of pattern`, and `1/all of them`.

Unsupported detection syntax, fields, modifiers, and logsources fail validation.
There is no correlation syntax, keyword selection, list-of-maps selection,
value expansion, or full wildcard escaping. Use trusted rule files:
Python regex has no built-in timeout and pathological regexes can be expensive.
Matching happens before output redaction.

## Coverage And Data Handling

The parser supports Codex rollout `session_meta`, `turn_context`, message events,
function/custom tool calls and outputs, and legacy local shell calls. It treats
JavaScript tool orchestration as recorded source text, without executing or
decoding nested code. It does not turn each nested call into a separate event.
It does not support `codex exec --json` event streams, compressed rollouts,
SQLite session stores, or every future rollout schema. Export plain rollout
JSONL for this version. Files without supported calls are flagged for review.

Inputs are read only and no recorded command is executed. A file is read only up
to its initial size; concurrently edited or truncated logs may be incomplete.
Malformed or excessively nested JSON records are reported and skipped; the
nesting limit is 100 levels. Tool arguments with excessive JSON nesting are
treated as raw text and diagnosed. Lines above 16 MiB stop that file with a
diagnostic. Memory scales with the largest session plus the compact
call-context index used for network correlation; it is not constant-memory.

URL credentials, query strings, fragments, authorization header values, common
credential assignments, AWS key IDs, and PEM private-key blocks are redacted
from reports. This is best effort: prompts, command bodies, outputs,
URL paths, and other fields can still contain secrets. Store reports accordingly.
POSIX output directory/file modes are 0700/0600; Windows protection depends on
the parent directory's ACLs. Source hashes cover original, unredacted lines and
are useful for locating evidence, not for proving a log is authentic.

## Validation

```sh
python3 -m unittest discover -s tests -v
```

See the [official Codex CLI documentation](https://learn.chatgpt.com/docs/codex/cli).
