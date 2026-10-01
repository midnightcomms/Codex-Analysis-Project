#!/usr/bin/env python3
"""AI session analysis for Codex by Codex: offline, single-run analysis. Python 3.9+, standard library only."""
import argparse
import ast
import fnmatch
import getpass
import hashlib
from html import escape
import json
import os
from pathlib import Path
import re
import shlex
import socket
import subprocess
import sys
from datetime import datetime, timedelta, timezone
from urllib.parse import urlsplit, urlunsplit

VERSION = "0.1.0"
MAX_JSON_DEPTH = 100
APP_NAME = "AI session analysis for Codex by Codex"
ASCII_BANNER = r"""
      ____ ___  ____  _______  __
     / ___/ _ \|  _ \| ____\ \/ /
    | |  | | | | | | |  _|  \  /
    | |__| |_| | |_| | |___ /  \
     \____\___/|____/|_____/_/\_\

    +-------------------------------------------+
    |  SESSION LOGS  ->  CONTEXT  ->  DETECTIONS |
    |                              ->  REPORT     |
    +-------------------------------------------+
""".strip("\n")
TAXONOMY_REVIEWED = "2026-09-28"
ATLAS_VERSION = "5.6.0"
ATLAS_SOURCE = "https://raw.githubusercontent.com/mitre-atlas/atlas-data/main/dist/ATLAS.yaml"
OWASP_SOURCE = "https://github.com/GenAI-Security-Project/GenAI-LLM-Top10/tree/main/2026/final"
# Curated official identifiers, not third-party incident-report crosswalks.
ATLAS = {
    "AML.T0010": "AI Supply Chain Compromise",
    "AML.T0037": "Data from Local System",
    "AML.T0043": "Craft Adversarial Data",
    "AML.T0050": "Command and Scripting Interpreter",
    "AML.T0051.001": "Indirect",
    "AML.T0052": "Phishing",
    "AML.T0053": "AI Agent Tool Invocation",
    "AML.T0055": "Unsecured Credentials",
    "AML.T0080.000": "Memory",
    "AML.T0080.001": "Thread",
    "AML.T0081": "Modify AI Agent Configuration",
    "AML.T0086": "Exfiltration via AI Agent Tool Invocation",
    "AML.T0092": "Manipulate User LLM Chat History",
    "AML.T0101": "Data Destruction via AI Agent Tool Invocation",
    "AML.T0110": "AI Agent Tool Poisoning",
}
OWASP = {
    "LLM01:2026": "Prompt Injection",
    "LLM02:2026": "Sensitive Information Disclosure",
    "LLM03:2026": "Excessive Agency",
    "LLM04:2026": "Supply Chain",
    "LLM05:2026": "Data and Model Poisoning",
    "LLM06:2026": "Unbounded Consumption",
    "LLM07:2026": "Misinformation",
    "LLM08:2026": "Hidden Context Exposure",
    "LLM09:2026": "Vector and Embedding Weaknesses",
    "LLM10:2026": "Improper Output Handling",
}
FIELDS = {"EventType", "CommandLine", "ToolName", "UserRequest", "AssistantContext",
          "Justification", "Output", "Cwd", "SandboxPermissions", "ContextMissing",
          "CommandDomains", "CommandURLs", "OutputDomains", "OutputURLs",
          "ObservedDomains", "ObservedURLs"}
URL_RE = re.compile(r"https?://[^\s<>\"'`\\]+", re.I)
PEM_BEGIN_RE = re.compile(r"-----BEGIN ([A-Z0-9 ]*PRIVATE KEY)-----", re.I)
DEFAULT_RULE_DIR = Path(__file__).resolve().parent / "rules" / "starter"
RULE_TEMPLATE_FIELDS = {"id", "title", "status", "level", "description", "references",
                        "logsource", "detection", "falsepositives", "investigation", "classification"}


class Condition:
    """Parse a deliberately limited condition grammar; never evaluate rule code."""
    def __init__(self, expression, names):
        if not isinstance(expression, str):
            raise ValueError("condition must be a string")
        self.tokens = re.findall(r"\(|\)|[A-Za-z0-9_*]+|\S", expression)
        self.pos = 0
        self.names = names
        self.tree = self.parse_or()
        if self.pos != len(self.tokens):
            raise ValueError("unexpected condition token")

    def take(self, token):
        if self.pos < len(self.tokens) and self.tokens[self.pos] == token:
            self.pos += 1
            return True
        return False

    def parse_or(self):
        node = self.parse_and()
        while self.take("or"):
            node = ("or", node, self.parse_and())
        return node

    def parse_and(self):
        node = self.atom()
        while self.take("and"):
            node = ("and", node, self.atom())
        return node

    def atom(self):
        if self.take("not"):
            return ("not", self.atom())
        if self.take("("):
            node = self.parse_or()
            if not self.take(")"):
                raise ValueError("missing closing parenthesis")
            return node
        if self.pos >= len(self.tokens):
            raise ValueError("incomplete condition")
        name = self.tokens[self.pos]
        self.pos += 1
        if name in ("1", "all"):
            if not self.take("of") or self.pos >= len(self.tokens):
                raise ValueError("expected 'of <selection pattern>'")
            pattern = self.tokens[self.pos]
            self.pos += 1
            names = [n for n in self.names if pattern == "them" or fnmatch.fnmatchcase(n, pattern)]
            if not names:
                raise ValueError("condition pattern matches no selections")
            return (name, names)
        if name not in self.names:
            raise ValueError("unknown selection: " + name)
        return ("selection", name)

    def matches(self, values, node=None):
        node = self.tree if node is None else node
        op = node[0]
        if op == "selection":
            return values[node[1]]
        if op in ("1", "all"):
            return (any if op == "1" else all)(values[n] for n in node[1])
        if op == "not":
            return not self.matches(values, node[1])
        a, b = self.matches(values, node[1]), self.matches(values, node[2])
        return a and b if op == "and" else a or b


def field_test(key, expected):
    field, *mods = key.split("|")
    if field not in FIELDS or any(m not in {"contains", "startswith", "endswith", "re", "all"} for m in mods):
        raise ValueError("unsupported field/modifier: " + key)
    modes = [m for m in mods if m != "all"]
    if len(modes) > 1 or len(set(mods)) != len(mods):
        raise ValueError("invalid modifier combination: " + key)
    mode = modes[0] if modes else "equal"
    values = expected if isinstance(expected, list) else [expected]
    if not values or any(not isinstance(v, (str, bool, int, float)) and v is not None for v in values):
        raise ValueError("field values must be nonempty scalar lists or scalars")
    if mode != "equal" and any(not isinstance(v, str) for v in values):
        raise ValueError("text modifiers require strings")
    patterns = [re.compile(v) for v in values] if mode == "re" else None

    def test(event):
        actual = event.get(field)
        actual_values = actual if isinstance(actual, list) else [actual]
        results = []
        for index, value in enumerate(values):
            matched = False
            for candidate in actual_values:
                if mode == "equal":
                    # Only * and ? are wildcards; square brackets remain literal.
                    if isinstance(value, str) and isinstance(candidate, str):
                        pattern = re.escape(value).replace(r"\*", ".*").replace(r"\?", ".")
                        matched = re.fullmatch(pattern, candidate, re.I | re.S) is not None
                    else:
                        matched = type(candidate) is type(value) and candidate == value
                elif not isinstance(candidate, str):
                    matched = False
                elif mode == "re":
                    matched = patterns[index].search(candidate) is not None
                else:
                    a, b = candidate.casefold(), value.casefold()
                    matched = b in a if mode == "contains" else a.startswith(b) if mode == "startswith" else a.endswith(b)
                if matched:
                    break
            results.append(matched)
        return (all if "all" in mods else any)(results)
    return test


class Rule:
    def __init__(self, raw):
        self.raw = raw
        if not isinstance(raw, dict) or not all(isinstance(raw.get(k), str) and raw[k] for k in ("id", "title", "level")):
            raise ValueError("rule requires id, title, level strings")
        if raw["level"] not in {"informational", "low", "medium", "high", "critical"}:
            raise ValueError("unsupported level")
        if raw.get("logsource") != {"product": "codex", "category": "ai_session"}:
            raise ValueError("logsource must be product=codex, category=ai_session")
        detection = raw.get("detection", {})
        if not isinstance(detection, dict):
            raise ValueError("detection must be an object")
        self.tests = {}
        for name, selection in detection.items():
            if name == "condition":
                continue
            if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", name) or name in {"and", "or", "not", "all", "of", "them"}:
                raise ValueError("invalid selection name")
            if not isinstance(selection, dict) or not selection:
                raise ValueError("only nonempty field-map selections are supported")
            self.tests[name] = [field_test(k, v) for k, v in selection.items()]
        self.matches_observed_network = any(
            key.split("|", 1)[0] in {"ObservedDomains", "ObservedURLs"}
            for name, selection in detection.items() if name != "condition"
            for key in selection)
        self.condition = Condition(detection.get("condition"), self.tests)
        self.classification = classify_rule(raw)

    def match(self, event):
        values = {name: all(test(event) for test in tests) for name, tests in self.tests.items()}
        return self.condition.matches(values), [name for name, value in values.items() if value]


def classify_rule(raw):
    mapping = raw.get("classification", {})
    if not isinstance(mapping, dict) or set(mapping) - {"atlas", "owasp_llm", "rationale"}:
        raise ValueError("invalid classification object")
    result = {"basis": "analyst_candidate_mapping", "reviewed_at": TAXONOMY_REVIEWED,
              "atlas_version": ATLAS_VERSION, "owasp_edition": "2026",
              "rationale": mapping.get("rationale", "No classification supplied for this rule.")}
    if not isinstance(result["rationale"], str) or not result["rationale"].strip():
        raise ValueError("classification requires a nonempty rationale")
    for field, catalog in (("atlas", ATLAS), ("owasp_llm", OWASP)):
        ids = mapping.get(field, [])
        if not isinstance(ids, list) or any(not isinstance(i, str) or i not in catalog for i in ids):
            raise ValueError("unknown or unsupported " + field + " classification ID")
        if len(ids) != len(set(ids)):
            raise ValueError("duplicate classification ID")
        result[field] = [{"id": i, "name": catalog[i],
                          "url": "https://atlas.mitre.org/techniques/" + i if field == "atlas" else OWASP_SOURCE}
                         for i in ids]
    return result


def classification_summary(rules, counts):
    return {
        "basis": "Candidate mappings of lexical rules; not measured detection coverage or confirmed techniques.",
        "reviewed_at": TAXONOMY_REVIEWED, "atlas_version": ATLAS_VERSION, "owasp_edition": "2026",
        "sources": {"atlas": ATLAS_SOURCE, "owasp_llm": OWASP_SOURCE},
        "finding_counts": counts,
        "unmapped_rules": {field: [r.raw["id"] for r in rules if not r.classification[field]]
                           for field in ("atlas", "owasp_llm")},
        "owasp_rule_coverage": [{"id": key, "name": name,
            "rule_ids": [r.raw["id"] for r in rules if any(m["id"] == key for m in r.classification["owasp_llm"])]}
            for key, name in OWASP.items()],
    }


def load_rules(paths):
    rules = []
    for selected in (DEFAULT_RULE_DIR, *paths):
        selected = Path(selected)
        if selected.is_dir():
            files = sorted(p for p in selected.iterdir() if p.is_file() and p.suffix.lower() in {".json", ".yaml", ".yml"})
            if not files:
                raise ValueError("rule directory has no detection files: " + str(selected))
        elif selected.is_file() and selected.suffix.lower() in {".json", ".yaml", ".yml"}:
            files = [selected]
        else:
            raise ValueError("rule file or directory unavailable: " + str(selected))
        for path in files:
            text = path.read_text(encoding="utf-8")
            if path.suffix.lower() in {".yaml", ".yml"}:
                try:
                    import yaml
                except ImportError as exc:
                    raise ValueError("YAML rules require PyYAML; JSON rules need no dependencies") from exc
                docs = list(yaml.safe_load_all(text))
                if len(docs) != 1:
                    raise ValueError("exactly one detection is required per file: " + str(path))
                raw = docs[0]
            else:
                raw = json.loads(text)
            if not isinstance(raw, dict):
                raise ValueError("exactly one detection object is required per file: " + str(path))
            missing = RULE_TEMPLATE_FIELDS - set(raw)
            if missing:
                raise ValueError("detection is missing template fields " + ", ".join(sorted(missing)) + ": " + str(path))
            if not isinstance(raw["description"], str) or not raw["description"].strip():
                raise ValueError("detection requires a description: " + str(path))
            if not isinstance(raw["investigation"], str) or not raw["investigation"].strip():
                raise ValueError("detection requires investigation guidance: " + str(path))
            for field in ("references", "falsepositives"):
                if not isinstance(raw[field], list) or any(not isinstance(v, str) for v in raw[field]):
                    raise ValueError("detection requires a string list for " + field + ": " + str(path))
            if not isinstance(raw["classification"], dict) or set(raw["classification"]) != {"atlas", "owasp_llm", "rationale"}:
                raise ValueError("detection requires atlas, owasp_llm, and rationale classification fields: " + str(path))
            rule = Rule(raw)
            rule.source_file = str(path.resolve())
            rules.append(rule)
    ids = [r.raw["id"] for r in rules]
    if len(ids) != len(set(ids)):
        raise ValueError("duplicate rule IDs")
    return rules


def content_text(value):
    if isinstance(value, str):
        return value
    if isinstance(value, list):
        return "\n".join(content_text(v) for v in value)
    if isinstance(value, dict):
        if "text" in value:
            return content_text(value["text"])
        return json.dumps(value, ensure_ascii=True)
    return "" if value is None else str(value)


def utc_time(seconds):
    return datetime.fromtimestamp(seconds, timezone.utc).isoformat()


def file_creation_time(path, stat):
    birth = getattr(stat, "st_birthtime", None)
    if birth is None and os.name == "nt":
        birth = stat.st_ctime
    if birth is None and sys.platform.startswith("linux"):
        try:
            result = subprocess.run(["stat", "-c", "%W", "--", str(path)],
                                    capture_output=True, text=True, timeout=2, check=False)
            if result.returncode == 0:
                value = int(result.stdout.strip())
                birth = value if value > 0 else None
        except (OSError, ValueError, subprocess.TimeoutExpired):
            pass
    return utc_time(birth) if birth is not None else None


def record_time(value):
    if not isinstance(value, str):
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        return parsed.astimezone(timezone.utc) if parsed.tzinfo else None
    except ValueError:
        return None


def json_depth_exceeded(value):
    pending = [(value, 1)]
    while pending:
        current, depth = pending.pop()
        if depth > MAX_JSON_DEPTH:
            return True
        if isinstance(current, dict):
            pending.extend((item, depth + 1) for item in current.values() if isinstance(item, (dict, list)))
        elif isinstance(current, list):
            pending.extend((item, depth + 1) for item in current if isinstance(item, (dict, list)))
    return False


def records(path, diagnostics, file_info=None):
    try:
        with path.open("rb") as stream:
            # Stop at the size seen at open, so an active session cannot extend the run.
            stat = os.fstat(stream.fileno())
            remaining = stat.st_size
            digest = hashlib.sha1() if file_info is not None else None
            if file_info is not None:
                file_info.update({"path": str(path), "size_bytes": stat.st_size,
                                  "created_at": file_creation_time(path, stat),
                                  "modified_at": utc_time(stat.st_mtime),
                                  "sha1": None, "hashed_bytes": 0})
            line = 0
            while remaining:
                data = stream.readline(min(remaining, 16 * 1024 * 1024 + 1))
                if not data:
                    break
                if digest is not None:
                    digest.update(data)
                    file_info["hashed_bytes"] += len(data)
                remaining -= len(data)
                line += 1
                if len(data) > 16 * 1024 * 1024:
                    diagnostics.append({"file": str(path), "line": line, "error": "line exceeds 16 MiB; remainder of file skipped"})
                    break
                if not data.strip():
                    continue
                try:
                    item = json.loads(data)
                    if not isinstance(item, dict):
                        raise ValueError("record must be an object")
                    if json_depth_exceeded(item):
                        diagnostics.append({"file": str(path), "line": line, "error": "JSON nesting exceeds " + str(MAX_JSON_DEPTH) + " levels"})
                        continue
                    yield line, item, hashlib.sha256(data).hexdigest()
                except (ValueError, UnicodeError):
                    diagnostics.append({"file": str(path), "line": line, "error": "invalid JSON record"})
                except RecursionError:
                    diagnostics.append({"file": str(path), "line": line, "error": "JSON nesting exceeds decoder limit"})
            if digest is not None:
                while remaining:
                    data = stream.read(min(remaining, 1024 * 1024))
                    if not data:
                        break
                    digest.update(data)
                    file_info["hashed_bytes"] += len(data)
                    remaining -= len(data)
                file_info["sha1"] = digest.hexdigest()
                if remaining:
                    diagnostics.append({"file": str(path), "error": "file shortened during scan; SHA-1 covers readable bytes only"})
    except OSError as exc:
        diagnostics.append({"file": str(path), "error": str(exc)})


def session_entry(inventory, session_id, path, identity_source):
    entry = inventory.setdefault(session_id, {
        "session_id": session_id, "identity_source": identity_source, "files": [],
        "computer_name": None, "computer_name_source": None,
        "user_name": None, "user_name_source": None,
        "operations": 0, "file_write_operations": 0, "file_change_candidates": 0,
        "unresolved_file_calls": 0,
        "network": {"http_references": 0, "https_references": 0,
                    "http_observations": 0, "https_observations": 0},
        "detections": {}, "findings": [],
    })
    if str(path) not in entry["files"]:
        entry["files"].append(str(path))
    return entry


def set_session_identity(entry, field, value, source):
    if not isinstance(value, str) or not value.strip():
        return
    value = value.strip()
    source_field = field + "_source"
    if entry[source_field] == "conflicting_session_metadata":
        return
    if entry[field] is not None and entry[field] != value:
        entry[field], entry[source_field] = None, "conflicting_session_metadata"
    else:
        entry[field], entry[source_field] = value, source


def parse_session(path, diagnostics, inventory=None, file_info=None):
    inventory = {} if inventory is None else inventory
    session, cwd, request, assistant = str(path), "", None, None
    identity_source = "file_fallback"
    events, pending = [], {}
    first_time = last_time = None
    for line, record, digest in records(path, diagnostics, file_info):
        timestamp = record_time(record.get("timestamp"))
        if timestamp is not None:
            first_time = timestamp if first_time is None else min(first_time, timestamp)
            last_time = timestamp if last_time is None else max(last_time, timestamp)
        payload = record.get("payload")
        if record.get("type") not in {"session_meta", "turn_context", "compacted", "response_item", "event_msg"}:
            continue
        if not isinstance(payload, dict):
            diagnostics.append({"file": str(path), "line": line, "error": "unsupported record without payload object"})
            continue
        kind, subtype = record.get("type"), payload.get("type")
        source = {"file": str(path), "line": line, "sha256": digest, "timestamp": record.get("timestamp")}
        if kind == "session_meta":
            new_session = payload.get("id") or payload.get("session_id")
            if isinstance(new_session, str) and new_session:
                if new_session != session:
                    request, assistant, pending = None, None, {}
                session, identity_source = new_session, "session_meta"
            cwd = payload.get("cwd", "")
            entry = session_entry(inventory, session, path, identity_source)
            for field, keys in (("computer_name", ("computer_name", "hostname", "host_name")),
                                ("user_name", ("user_name", "username", "os_user"))):
                for key in keys:
                    if isinstance(payload.get(key), str) and payload[key].strip():
                        set_session_identity(entry, field, payload[key], "session_metadata:" + key)
                        break
        elif kind == "turn_context":
            cwd = payload.get("cwd", cwd)
        elif kind == "compacted" or (kind == "event_msg" and subtype in {"task_complete", "turn_aborted"}):
            request, assistant = None, None
        elif (kind == "response_item" and subtype == "message") or (kind == "event_msg" and subtype in {"user_message", "agent_message"}):
            session_entry(inventory, session, path, identity_source)
            role = payload.get("role") or ("user" if subtype == "user_message" else "assistant")
            value = content_text(payload.get("content", payload.get("message")))
            if role == "user":
                request, assistant = {"text": value, "source": source}, None
            elif role == "assistant" and payload.get("channel") != "analysis":
                assistant = {"text": value, "source": source}
        elif kind == "response_item" and subtype in {"function_call", "custom_tool_call", "local_shell_call"}:
            session_entry(inventory, session, path, identity_source)
            raw = payload.get("arguments", payload.get("input", payload.get("action", {})))
            args = raw
            if isinstance(raw, str):
                try:
                    args = json.loads(raw)
                except ValueError:
                    args = {"input": raw}
                except RecursionError:
                    diagnostics.append({"file": str(path), "line": line, "error": "tool arguments exceed JSON decoder nesting limit; using raw input"})
                    args = {"input": raw}
                if json_depth_exceeded(args):
                    diagnostics.append({"file": str(path), "line": line, "error": "tool arguments exceed " + str(MAX_JSON_DEPTH) + " nesting levels; using raw input"})
                    args = {"input": raw}
            if not isinstance(args, dict):
                args = {"input": content_text(args)}
            command = args.get("cmd", args.get("command", args.get("input", json.dumps(args))))
            if isinstance(command, list):
                command = json.dumps(command)
            call_id = payload.get("call_id", payload.get("id"))
            if call_id is not None and not isinstance(call_id, str):
                diagnostics.append({"file": str(path), "line": line, "error": "invalid call ID; result correlation disabled"})
                call_id = None
            event = {"EventType": "tool_call", "session_id": session, "call_id": call_id,
                     "ToolName": payload.get("name", "local_shell"), "CommandLine": content_text(command),
                     "UserRequest": request["text"] if request else "",
                     "AssistantContext": assistant["text"] if assistant else "",
                     "Justification": content_text(args.get("justification")),
                     "SandboxPermissions": content_text(args.get("sandbox_permissions")),
                     "Cwd": args.get("workdir", args.get("cwd", cwd)), "Output": "",
                     "ContextMissing": request is None, "source": source,
                     "context_sources": {"user_request": request, "assistant_statement": assistant},
                     "execution_status": "call_recorded_result_missing",
                     "intent_assessment": "Recorded statements only; authorization and actual intent unverified."}
            event["CommandDomains"], event["CommandURLs"] = url_indicators(event["CommandLine"])
            event["OutputDomains"], event["OutputURLs"] = [], []
            event["ObservedDomains"], event["ObservedURLs"] = [], []
            events.append(event)
            if call_id:
                if call_id in pending:
                    diagnostics.append({"file": str(path), "line": line, "error": "duplicate call ID"})
                    pending[call_id] = None
                else:
                    pending[call_id] = event
        elif kind == "response_item" and subtype in {"function_call_output", "custom_tool_call_output"}:
            call_id = payload.get("call_id")
            event = pending.get(call_id) if isinstance(call_id, str) else None
            if event is not None:
                event["Output"] = content_text(payload.get("output"))
                event["OutputDomains"], event["OutputURLs"] = url_indicators(event["Output"])
                event["result_source"] = source
                event["execution_status"] = "tool_result_recorded_success_unverified"
            else:
                diagnostics.append({"file": str(path), "line": line, "error": "unmatched tool result"})
    if file_info is not None:
        file_info.update({"first_record_at": first_time.isoformat() if first_time else None,
                          "last_record_at": last_time.isoformat() if last_time else None,
                          "session_length_seconds": (last_time - first_time).total_seconds() if first_time else None})
    return events


def file_write_indicators(event):
    """Count candidate write operations, never claim successful filesystem changes."""
    command = event["CommandLine"]
    tool = str(event["ToolName"]).split(".")[-1].lower()
    reasons = []
    targets = re.findall(r"\*\*\* (?:Add|Update) File: ([^\r\n]+)", command)
    if targets:
        reasons.append("patch_add_or_update")
    if tool in {"write_file", "edit_file", "replace_in_file", "create_file"}:
        reasons.append("file_write_tool")
    patterns = {
        "file_write_api": r"(?i)\.(?:write_text|write_bytes|writeFile|writeFileSync|appendFile|appendFileSync)\s*\(|\bopen\([^\n]*,\s*[\"'][wax]",
        "shell_file_mutation": r"(?i)(?:^|[\s;|&])(?:touch|mkdir|cp|mv|install|truncate|tee|Set-Content|Add-Content|Out-File|Copy-Item|Move-Item|New-Item)\s|\bsed\s+-i\b",
        "shell_redirection": r"(?:^|[\s;])(?:[012]?)>{1,2}\s*[^\s&]|[^\s=]>\s*(?:/|~|[A-Za-z_.])",
        "download_to_file": r"(?i)\bcurl\b[^\n]*(?:\s-[oO](?:\s|$)|--output\b)|\bwget\b[^\n]*(?:\s-O\s|--output-document\b)",
    }
    for reason, pattern in patterns.items():
        if re.search(pattern, command):
            reasons.append(reason)
    return {"candidate": bool(reasons), "reasons": reasons,
            "patch_targets": [target.split(r"\n", 1)[0].strip() for target in targets],
            "basis": "Lexical indicators; one count per tool call, not per file or successful write."}


def file_change_candidates(event):
    """Extract declared file targets; never infer a successful filesystem change."""
    command = event["CommandLine"]
    tool = str(event["ToolName"]).split(".")[-1].lower()
    changes, seen = [], set()

    def add(operation, path, basis):
        if not isinstance(path, str):
            return
        path = path.strip().strip('"\'')
        if not path or len(path) > 2048 or path in {"-", "/dev/null"}:
            return
        key = (operation, path, basis)
        if key not in seen:
            changes.append({"operation": operation, "path": path, "basis": basis})
            seen.add(key)

    patch_inputs = [command] if "apply_patch" in tool else []
    for match in re.finditer(r"\btools\.apply_patch\s*\(\s*((?:\"(?:\\.|[^\"\\])*\")|(?:'(?:\\.|[^'\\])*'))", command):
        try:
            patch_inputs.append(ast.literal_eval(match.group(1)))
        except (SyntaxError, ValueError):
            pass
    for call in re.finditer(r"\btools\.apply_patch\s*\(\s*([A-Za-z_][A-Za-z0-9_]*)\s*\)", command):
        name = re.escape(call.group(1))
        assignment = re.search(r"\b(?:const|let|var)\s+" + name + r"\s*=\s*((?:\"(?:\\.|[^\"\\])*\")|(?:'(?:\\.|[^'\\])*'))", command)
        if assignment:
            try:
                patch_inputs.append(ast.literal_eval(assignment.group(1)))
            except (SyntaxError, ValueError):
                pass
    for patch in patch_inputs:
        if not isinstance(patch, str):
            continue
        previous_update = None
        for match in re.finditer(r"(?m)^\*\*\* (Add File|Update File|Delete File|Move to): ([^\r\n]+)", patch):
            action, path = match.groups()
            if action == "Add File":
                add("created", path, "patch_add")
                previous_update = None
            elif action == "Update File":
                add("modified", path, "patch_update")
                previous_update = path.strip()
            elif action == "Delete File":
                add("deleted", path, "patch_delete")
                previous_update = None
            elif previous_update:
                changes[:] = [item for item in changes if not (item["operation"] == "modified" and item["path"] == previous_update and item["basis"] == "patch_update")]
                add("deleted", previous_update, "patch_move_source")
                add("created", path, "patch_move_destination")
                previous_update = None
    if patch_inputs:
        return changes

    shell_inputs = []
    if "tools.exec_command" in command:
        for match in re.finditer(r"\bcmd\s*:\s*((?:\"(?:\\.|[^\"\\])*\")|(?:'(?:\\.|[^'\\])*'))", command):
            try:
                shell_inputs.append(ast.literal_eval(match.group(1)))
            except (SyntaxError, ValueError):
                pass
    elif tool in {"exec_command", "local_shell", "shell", "terminal"}:
        shell_inputs.append(command)

    for shell in shell_inputs:
        if not isinstance(shell, str):
            continue
        if re.match(r"\s*(?:python(?:[23](?:\.\d+)?)?|py)(?:\s|$)", shell, re.I):
            for match in re.finditer(r"\bPath\(\s*(['\"])([^'\"\n]+)\1\s*\)\.(write_text|write_bytes|unlink)\s*\(", shell):
                add("deleted" if match.group(3) == "unlink" else "created_or_modified", match.group(2), "python_path_api")
            for match in re.finditer(r"\bopen\(\s*(['\"])([^'\"\n]+)\1\s*,\s*(['\"])([wax][^'\"\n]*)\3", shell):
                add("created" if match.group(4).startswith("x") else "created_or_modified", match.group(2), "python_open_mode")
        lexer = shlex.shlex(shell.replace("\n", ";"), posix=True, punctuation_chars=";&|<>")
        lexer.whitespace_split = True
        try:
            tokens = list(lexer)
        except ValueError:
            continue
        segments, segment = [], []
        for token in tokens:
            if token in {";", "&&", "||", "|"}:
                if segment:
                    segments.append(segment)
                segment = []
            else:
                segment.append(token)
        if segment:
            segments.append(segment)
        for segment in segments:
            for index, token in enumerate(segment[:-1]):
                if token in {">", ">>"}:
                    add("created_or_modified", segment[index + 1], "shell_redirection")
            words = []
            skip = False
            for word in segment:
                if skip:
                    skip = False
                elif word in {">", ">>", "<"}:
                    skip = True
                else:
                    words.append(word)
            if not words:
                continue
            verb = Path(words[0]).name.lower()
            operands = [word for word in words[1:] if not word.startswith("-")]
            if verb in {"rm", "unlink"}:
                for path in operands:
                    add("deleted", path, "shell_delete")
            elif verb == "touch":
                for path in operands:
                    add("created_or_modified", path, "shell_touch")
            elif verb in {"cp", "install"} and len(operands) >= 2:
                add("created_or_modified", operands[-1], "shell_copy_destination")
            elif verb == "mv" and len(operands) == 2:
                add("deleted", operands[0], "shell_move_source")
                add("created", operands[1], "shell_move_destination")
            elif verb == "tee":
                for path in operands:
                    add("created_or_modified", path, "shell_tee")
            elif verb == "sed" and any(word == "-i" or word.startswith("--in-place") for word in words[1:]) and operands:
                add("modified", operands[-1], "shell_in_place_edit")
            elif verb in {"curl", "wget"}:
                for index, word in enumerate(words[:-1]):
                    if word in ({"-o", "--output"} if verb == "curl" else {"-O", "--output-document"}):
                        add("created_or_modified", words[index + 1], "download_output")
    return changes


def add_network_item(inventory, record):
    """Group redacted destinations while retaining each evidence/context association."""
    record = scrub(record)
    entry = inventory.setdefault(record["url"], {
        "url": record["url"], "domain": record["host"],
        "references": 0, "observations": 0, "items": [],
    })
    reference = record["evidence_type"] == "session_url_reference"
    entry["references" if reference else "observations"] += 1
    item = {key: record.get(key) for key in (
        "evidence_type", "field", "session_id", "call_id", "source", "correlation", "method", "status", "timestamp")}
    context = record.get("context") or {}
    item["context"] = {}
    for key in ("ToolName", "CommandLine", "UserRequest", "AssistantContext", "Justification"):
        value = context.get(key, "")
        item["context"][key] = value[:3000] + ("\n[excerpt truncated]" if len(value) > 3000 else "")
    item["context_sources"] = {key: value.get("source") for key, value in context.get("context_sources", {}).items() if value}
    item["action_source"] = context.get("source")
    entry["items"].append(item)


def atlas_heat_style(count, maximum):
    if count <= 0 or maximum <= 0:
        return "background-color:#f0f3f3;color:#4f585c"
    intensity = 0.18 + 0.82 * (count / maximum) ** 0.7
    pale, dark = (255, 232, 226), (116, 20, 37)
    channels = tuple(round(start + (end - start) * intensity) for start, end in zip(pale, dark))
    foreground = "#ffffff" if intensity >= 0.65 else "#24282b"
    return "background-color:#{:02x}{:02x}{:02x};color:{}".format(*channels, foreground)


def session_timelines(output):
    """Join generated logs by source record, not potentially reused call IDs."""
    def rows(name):
        with (output / (name + ".jsonl")).open(encoding="utf-8") as stream:
            for line in stream:
                yield json.loads(line)

    def key(session_id, source):
        if not isinstance(source, dict):
            return None
        return (str(session_id), source.get("file"), source.get("line"), source.get("sha256"))

    timelines, by_source, by_call = {}, {}, {}
    for event in rows("events"):
        session_id = event["session_id"]
        source = event["source"]
        timestamp = record_time(source.get("timestamp"))
        entry = {"timestamp": timestamp.isoformat() if timestamp else None,
                 "source": source, "call_id": event["call_id"], "tool": event["ToolName"],
                 "command": event["CommandLine"][:400], "user_request": event["UserRequest"][:400],
                 "assistant_context": event["AssistantContext"][:400],
                 "execution_status": event["execution_status"],
                 "file_write": event["file_write"]["candidate"],
                 "file_changes": event.get("file_changes", []), "detections": [],
                 "network": {"http_references": 0, "https_references": 0,
                             "http_observations": 0, "https_observations": 0},
                 "network_urls": []}
        timelines.setdefault(session_id, []).append(entry)
        by_source[key(session_id, source)] = entry
        if event["call_id"]:
            by_call.setdefault((session_id, event["call_id"]), []).append(entry)

    finding_index = {}
    for finding in rows("findings"):
        session_id = finding["event"]["session_id"]
        index = finding_index.get(session_id, 0)
        finding_index[session_id] = index + 1
        event = finding["event"]
        entry = by_source.get(key(session_id, event.get("parent_source") or event["source"]))
        if entry is not None:
            entry["detections"].append({"rule_id": finding["rule_id"], "title": finding["title"],
                                        "level": finding["level"], "finding_index": index})

    for protocol in ("http", "https"):
        for network in rows(protocol):
            observation = network["evidence_type"] == "imported_network_observation"
            if observation and network.get("correlation") != "exact_session_and_call_id":
                continue
            session_id = network.get("session_id")
            context = network.get("context")
            entry = by_source.get(key(session_id, context.get("source"))) if isinstance(context, dict) else None
            if entry is None:
                matches = by_call.get((session_id, network.get("call_id")), [])
                entry = matches[0] if len(matches) == 1 else None
            if entry is None:
                continue
            field = protocol + ("_observations" if observation else "_references")
            entry["network"][field] += 1
            if network["url"] not in entry["network_urls"] and len(entry["network_urls"]) < 5:
                entry["network_urls"].append(network["url"])

    for entries in timelines.values():
        entries.sort(key=lambda entry: (entry["timestamp"] is None, entry["timestamp"] or "",
                                        str(entry["source"].get("file", "")), entry["source"].get("line", 0)))
    return timelines


def render_html(summary):
    """Untrusted session content is text only, with no external assets or scripts."""
    def e(value):
        return escape(str(value), quote=True)

    def table(headers, rows):
        return '<div class="table-scroll"><table><thead><tr>' + ''.join('<th scope="col">' + e(h) + '</th>' for h in headers) + '</tr></thead><tbody>' + ''.join(rows) + '</tbody></table></div>'

    sessions = sorted(summary["sessions"], key=lambda s: (-len(s["findings"]), s["session_id"]))
    session_files = summary.get("session_files", [])
    file_index = {item["path"]: index for index, item in enumerate(session_files)}
    totals = summary["counts"]
    body = ['<header><p class="eyebrow">CODEX / SESSION ANALYSIS</p><h1>' + e(APP_NAME) + '</h1>',
            '<p class="muted">' + e(summary["generated_at"]) + ' &middot; ' + e(summary["rules"]) + ' rules loaded</p></header>']
    body.append('<section class="metrics" aria-label="Run totals">')
    for label, number in (("Sessions", totals["sessions"]), ("With detections", totals["sessions_with_detections"]),
                          ("Operations", totals["events"]), ("File-write indicators", totals["file_write_operations"]),
                          ("Network items", totals["http"] + totals["https"])):
        body.append('<div><strong>' + e(number) + '</strong><span>' + e(label) + '</span></div>')
    body.append('</section>')
    if summary["partial"]:
        body.append('<p class="notice">Partial coverage: ' + e(len(summary["diagnostics"])) + ' input diagnostics. Counts reflect readable, supported records.</p>')
    body.append('<p class="definitions">Operations are recorded tool calls. File-write indicators count calls with write syntax, not successful writes or distinct files. Network references do not prove traffic; observations are supplied by imported logs. Repeated records are counted.</p>')
    body.append('<nav aria-label="Report sections"><a href="#atlas-heatmap">ATLAS heatmap</a> &middot; <a href="#file-changes">File changes</a> &middot; <a href="#session-files">Session files</a> &middot; <a href="#network-inventory">Domains and URLs</a> &middot; <a href="#sessions">Session timelines and detections</a></nav>')
    atlas_counts = summary["classification"]["finding_counts"]["atlas"]
    maximum = max(atlas_counts.values(), default=0)
    flagged = sum(atlas_counts.get(technique, 0) > 0 for technique in ATLAS)
    body.append('<section id="atlas-heatmap"><h2>MITRE ATLAS Heatmap</h2>')
    body.append('<p><strong>' + e(flagged) + ' of ' + e(len(ATLAS)) + '</strong> supported techniques have mapped findings &middot; ' + e(sum(atlas_counts.values())) + ' technique matches</p>')
    body.append('<p class="definitions">The grid covers the 15 ATLAS identifiers recognized by this analyzer, not the full ATLAS matrix. Each cell counts findings mapped to that technique. Darker cells have more matches within this report. One finding can map to multiple techniques; mappings are analyst candidates, not confirmed techniques.</p>')
    body.append('<div class="atlas-grid" role="group" aria-label="ATLAS technique finding counts">')
    for index, (technique, name) in enumerate(ATLAS.items()):
        count = atlas_counts.get(technique, 0)
        tag = 'a href="#atlas-detail-' + str(index) + '"' if count else 'div'
        body.append('<' + tag + ' class="atlas-cell" data-count="' + e(count) + '" style="' + atlas_heat_style(count, maximum) + '" aria-label="' + e(technique + ' ' + name + ': ' + str(count) + ' findings') + '"><span class="atlas-id">' + e(technique) + '</span><strong>' + e(count) + '</strong><span class="atlas-name">' + e(name) + '</span></' + ('a' if count else 'div') + '>')
    body.append('</div>')
    for index, (technique, name) in enumerate(ATLAS.items()):
        count = atlas_counts.get(technique, 0)
        if not count:
            continue
        body.append('<details id="atlas-detail-' + str(index) + '" class="atlas-detail"><summary>' + e(technique + ' ' + name) + ' (' + e(count) + ' findings)</summary><ul>')
        for session_index, session in enumerate(sessions):
            for finding_index, finding in enumerate(session["findings"]):
                if any(mapping["id"] == technique for mapping in finding["classification"]["atlas"]):
                    body.append('<li><a href="#finding-' + str(session_index) + '-' + str(finding_index) + '">' + e(finding["title"]) + '</a> &middot; ' + e(session["session_id"]) + ' &middot; Call ' + e(finding["call_id"]) + '</li>')
        body.append('</ul></details>')
    body.append('</section>')
    inventory_position = len(body)
    body.append('<h2 id="sessions">Sessions</h2>')
    body.append('<p class="definitions">Computer and user names come from explicit session metadata when present. For the default local Codex store, missing values name this analysis computer and account; they do not independently prove where an imported or copied session originated. Unknown means no supported attribution was available.</p>')
    rows = []
    for index, session in enumerate(sessions):
        network = session["network"]
        label = str(len(session["findings"])) + ' findings' if session["findings"] else 'No detections'
        cells = ['<a href="#session-' + str(index) + '">' + e(session["session_id"]) + '</a>',
                 e(session["computer_name"] or "Unknown"), e(session["user_name"] or "Unknown"),
                 e(session["operations"]), e(session["file_write_operations"]),
                 e(network["http_references"]), e(network["https_references"]),
                 e(network["http_observations"]), e(network["https_observations"]),
                 '<span class="' + ('flag' if session["findings"] else 'clear') + '">' + e(label) + '</span>']
        rows.append('<tr>' + ''.join('<td>' + value + '</td>' for value in cells) + '</tr>')
    body.append(table(["Session ID", "Computer", "User", "Operations", "Write indicators", "HTTP refs", "HTTPS refs", "HTTP observed", "HTTPS observed", "Detections"], rows))
    if not sessions:
        body.append('<p>No identifiable sessions found in the selected inputs.</p>')
    call_links = {}
    for session_index, session in enumerate(sessions):
        for call_index, entry in enumerate(session.get("timeline", [])):
            source = entry["source"]
            call_links[(session["session_id"], source.get("file"), source.get("line"), source.get("sha256"))] = "#call-" + str(session_index) + "-" + str(call_index)
    body.append('<section id="file-changes"><h2>File Changes</h2>')
    body.append('<p class="definitions">These are candidate paths and operations declared in recorded tool inputs, not confirmed filesystem changes. A create/modify label means the command could do either. Relative paths retain the recorded working directory. Shell targets may be directories; nested or dynamic scripts and implicit writes can be missed.</p>')
    file_inventory = summary.get("file_inventory", [])
    for operation, label in (("created", "Created"), ("modified", "Modified"),
                             ("deleted", "Deleted"), ("created_or_modified", "Create or modify")):
        items = [item for item in file_inventory if item["operation"] == operation]
        body.append('<h3>' + label + ' (' + e(len(items)) + ')</h3>')
        if not items:
            body.append('<p class="muted">No identified targets.</p>')
            continue
        change_rows = []
        for item in items:
            source = item["source"]
            link = call_links.get((item["session_id"], source.get("file"), source.get("line"), source.get("sha256")))
            call = ('<a href="' + e(link) + '">' + e(item["call_id"] or "unidentified") + '</a>') if link else e(item["call_id"] or "unidentified")
            cells = ['<code>' + e(item["path"]) + '</code>', e(item["cwd"] or "Unknown"),
                     e(item["session_id"]), call, e(item["basis"]),
                     e(source.get("file", "")) + ':' + e(source.get("line", ""))]
            change_rows.append('<tr>' + ''.join('<td>' + cell + '</td>' for cell in cells) + '</tr>')
        body.append(table(["Path as recorded", "Working directory", "Session", "Call", "Evidence basis", "Source"], change_rows))
    unresolved = summary.get("unresolved_file_calls", [])
    body.append('<h3>Unresolved write targets (' + e(len(unresolved)) + ')</h3>')
    body.append('<p class="definitions">These calls have a write indicator but no extractable target path; they are not counted as identified files.</p>')
    if unresolved:
        unresolved_rows = []
        for item in unresolved:
            source = item["source"]
            link = call_links.get((item["session_id"], source.get("file"), source.get("line"), source.get("sha256")))
            call = ('<a href="' + e(link) + '">' + e(item["call_id"] or "unidentified") + '</a>') if link else e(item["call_id"] or "unidentified")
            cells = [e(item["session_id"]), call, e(', '.join(item["reasons"])),
                     e(source.get("file", "")) + ':' + e(source.get("line", ""))]
            unresolved_rows.append('<tr>' + ''.join('<td>' + cell + '</td>' for cell in cells) + '</tr>')
        body.append(table(["Session", "Call", "Indicator", "Source"], unresolved_rows))
    body.append('</section>')
    body.append('<h2 id="session-files">Session Files</h2>')
    body.append('<p class="definitions">SHA-1 covers the file bytes read up to the size recorded at scan time. Created and modified times are filesystem metadata in UTC; creation time may be unavailable. Session length is the elapsed span from the earliest to latest valid JSONL record timestamp.</p>')
    file_rows = []
    for index, item in enumerate(session_files):
        associated = [s["session_id"] for s in sessions if item["path"] in s["files"]]
        duration = item["session_length_seconds"]
        cells = ['<span id="file-' + str(index) + '">' + e(item["path"]) + '</span>',
                 e(', '.join(associated) or 'Unidentified'),
                 '<code>' + e(item["sha1"] or 'Unavailable') + '</code>',
                 e(item["created_at"] or 'Unavailable'), e(item["modified_at"] or 'Unavailable'),
                 e(item["first_record_at"] or 'Unavailable'), e(item["last_record_at"] or 'Unavailable'),
                 e(str(timedelta(seconds=duration)) if duration is not None else 'Unavailable')]
        file_rows.append('<tr>' + ''.join('<td>' + cell + '</td>' for cell in cells) + '</tr>')
    body.append(table(["JSONL file", "Session ID", "SHA-1", "Created (UTC)", "Modified (UTC)",
                       "First record (UTC)", "Last record (UTC)", "Session length"], file_rows))
    for index, session in enumerate(sessions):
        body.append('<section class="session" id="session-' + str(index) + '"><h2>' + e(session["session_id"]) + '</h2>')
        body.append('<p class="muted">Computer: ' + e(session["computer_name"] or "Unknown") + ' (' + e(session["computer_name_source"] or "not recorded") + ') &middot; User: ' + e(session["user_name"] or "Unknown") + ' (' + e(session["user_name_source"] or "not recorded") + ')</p>')
        body.append('<p class="muted">Session ID source: ' + e(session["identity_source"]) + ' &middot; ' + e(session["operations"]) + ' operations &middot; ' + e(session["file_write_operations"]) + ' file-write indicators</p>')
        body.append('<details><summary>Source files (' + str(len(session["files"])) + ')</summary><ul>' + ''.join('<li><a href="#file-' + str(file_index[p]) + '">' + e(p) + '</a></li>' if p in file_index else '<li>' + e(p) + '</li>' for p in session["files"]) + '</ul></details>')
        timeline = session.get("timeline", [])
        body.append('<h3>Activity Timeline</h3>')
        body.append('<p class="definitions">Rows use the recorded tool-call time in UTC. Network counts are associated with the call; they do not establish when a request occurred. Red marks detections, amber marks write indicators, teal marks network items, and gray marks other calls.</p>')
        if not timeline:
            body.append('<p class="muted">No supported tool calls were recorded for this session.</p>')
        else:
            body.append('<ol class="timeline">')
            for call_index, entry in enumerate(timeline):
                timestamp = record_time(entry.get("timestamp"))
                network = entry["network"]
                network_count = sum(network.values())
                tone = "alert" if entry["detections"] else "write" if entry["file_write"] or entry["file_changes"] else "network" if network_count else "plain"
                body.append('<li id="call-' + str(index) + '-' + str(call_index) + '" class="tone-' + tone + '"><time class="timeline-time"' + (' datetime="' + e(entry["timestamp"]) + '"' if timestamp else '') + '>')
                if timestamp:
                    body.append('<span>' + e(timestamp.strftime("%Y-%m-%d")) + '</span><span>' + e(timestamp.strftime("%H:%M:%S")) + ' UTC</span>')
                else:
                    body.append('<span>Time</span><span>unavailable</span>')
                body.append('</time><div class="timeline-entry"><div class="timeline-heading"><strong>' + e(entry["tool"]) + '</strong><code>Call ' + e(entry["call_id"] or 'unidentified') + '</code></div>')
                body.append('<div class="timeline-signals">')
                if entry["detections"]:
                    body.append('<span class="signal signal-alert">' + e(len(entry["detections"])) + ' detections</span>')
                if entry["file_write"]:
                    body.append('<span class="signal signal-write">Write indicator</span>')
                if entry["file_changes"]:
                    body.append('<span class="signal signal-write">' + e(len(entry["file_changes"])) + ' file targets</span>')
                if network_count:
                    body.append('<span class="signal signal-network">' + e(network_count) + ' network items</span>')
                body.append('</div><pre class="timeline-command">' + e(entry["command"] or '(no command text)') + '</pre>')
                body.append('<details><summary>Context and evidence</summary>')
                for label, field in (("User request", "user_request"), ("Assistant statement", "assistant_context")):
                    if entry[field]:
                        body.append('<p><strong>' + label + ':</strong> ' + e(entry[field]) + '</p>')
                if entry["detections"]:
                    body.append('<p><strong>Detections</strong></p><ul>')
                    for detection in entry["detections"]:
                        body.append('<li><a href="#finding-' + str(index) + '-' + str(detection["finding_index"]) + '">' + e(detection["title"]) + '</a> <code>' + e(detection["rule_id"]) + '</code></li>')
                    body.append('</ul>')
                if entry["file_changes"]:
                    body.append('<p><strong>Candidate file changes</strong> &middot; <a href="#file-changes">File inventory</a></p><ul>')
                    for change in entry["file_changes"]:
                        body.append('<li>' + e(change["operation"].replace('_', ' ')) + ': <code>' + e(change["path"]) + '</code></li>')
                    body.append('</ul>')
                if network_count:
                    body.append('<p><strong>Network:</strong> HTTP ' + e(network["http_references"]) + ' references / ' + e(network["http_observations"]) + ' observed; HTTPS ' + e(network["https_references"]) + ' references / ' + e(network["https_observations"]) + ' observed. <a href="#network-inventory">Destination inventory</a></p>')
                    if entry["network_urls"]:
                        body.append('<ul>' + ''.join('<li><code>' + e(url) + '</code></li>' for url in entry["network_urls"]) + '</ul>')
                body.append('<p class="muted">Result: ' + e(entry["execution_status"]) + ' &middot; Source: ' + e(entry["source"]["file"]) + ':' + e(entry["source"]["line"]) + '</p></details></div></li>')
            body.append('</ol>')
        if not session["findings"]:
            body.append('<p class="clear">No detections in the supported records. This does not establish that the session is safe.</p></section>')
            continue
        detection_rows = []
        for detection in session["detections"]:
            detection_rows.append('<tr><td>' + e(detection["level"].upper()) + '</td><td>' + e(detection["title"]) + '<br><code>' + e(detection["rule_id"]) + '</code></td><td>' + e(detection["count"]) + '</td></tr>')
        body.append(table(["Severity", "Detection", "Count"], detection_rows))
        body.append('<details class="evidence" open><summary>Finding evidence (' + str(len(session["findings"])) + ')</summary>')
        for finding_index, finding in enumerate(session["findings"]):
            body.append('<article id="finding-' + str(index) + '-' + str(finding_index) + '"><h3><span class="flag">' + e(finding["level"].upper()) + '</span> ' + e(finding["title"]) + '</h3>')
            body.append('<p><code>' + e(finding["rule_id"]) + '</code> &middot; Call: ' + e(finding["call_id"]) + '</p>')
            if finding.get("rule_file"):
                body.append('<p>Detection file: ' + e(finding["rule_file"]) + '</p>')
            for label, key in (("Command / tool input", "command"), ("User request", "user_request"), ("Assistant statement", "assistant_context"), ("Justification", "justification"), ("Tool result", "output")):
                body.append('<h4>' + label + '</h4><pre>' + e(finding[key] or '(not recorded)') + '</pre>')
            body.append('<p>Evidence: ' + e(finding["source"]["file"]) + ':' + e(finding["source"]["line"]) + '</p>')
            if finding["result_source"]:
                body.append('<p>Tool result: ' + e(finding["result_source"]["file"]) + ':' + e(finding["result_source"]["line"]) + '</p>')
            labels = [item["id"] + ' ' + item["name"] for field in ("atlas", "owasp_llm") for item in finding["classification"][field]]
            body.append('<p class="muted">Candidate classification: ' + e('; '.join(labels) or 'Unmapped') + '</p>')
            body.append('<p>' + e(finding["investigation"]) + '</p></article>')
        body.append('</details></section>')
    inventory = summary.get("network_inventory", {"domains": [], "urls": []})
    inventory_start = len(body)
    body.append('<section id="network-inventory"><h2>Unique Domains and URLs</h2>')
    body.append('<p>' + e(len(inventory["domains"])) + ' unique hosts &middot; ' + e(len(inventory["urls"])) + ' unique redacted URLs. Hosts include subdomains and IP addresses. Credentials, query values and fragments are removed or redacted before grouping, so distinct raw URLs may merge.</p>')
    body.append('<p class="definitions">References are mentions, not confirmed requests. Imported observations report traffic but do not independently prove causation. Context is the recorded prompt and action associated with the call; it is not verified intent. Unmatched observations have no attributed prompt or action.</p>')
    domain_rows = []
    for index, domain in enumerate(inventory["domains"]):
        domain_rows.append('<tr><td><a href="#domain-' + str(index) + '">' + e(domain["domain"]) + '</a></td><td>' + e(domain["url_count"]) + '</td><td>' + e(domain["references"]) + '</td><td>' + e(domain["observations"]) + '</td></tr>')
    body.append(table(["Domain / host", "Unique URLs", "References", "Observed items"], domain_rows))
    for index, domain in enumerate(inventory["domains"]):
        body.append('<h3 id="domain-' + str(index) + '">' + e(domain["domain"]) + '</h3>')
        for destination in inventory["urls"]:
            if destination["domain"] != domain["domain"]:
                continue
            body.append('<details><summary>' + e(destination["url"]) + ' (' + e(destination["references"]) + ' references, ' + e(destination["observations"]) + ' observed items)</summary>')
            for item in destination["items"]:
                body.append('<article><h4>' + e(item["evidence_type"]) + '</h4><p>Session: ' + e(item["session_id"]) + ' &middot; Call: ' + e(item["call_id"]) + ' &middot; Field: ' + e(item["field"] or 'imported observation') + ' &middot; Correlation: ' + e(item["correlation"] or 'recorded reference') + '</p>')
                for label, key in (("Tool", "ToolName"), ("Action / tool input", "CommandLine"), ("User prompt", "UserRequest"), ("Assistant statement", "AssistantContext"), ("Justification", "Justification")):
                    body.append('<h4>' + label + '</h4><pre>' + e(item["context"][key] or '(not recorded / unattributed)') + '</pre>')
                body.append('<p>Evidence: ' + e(json.dumps(item["source"])) + '</p><p>Action source: ' + e(json.dumps(item["action_source"])) + '</p><p>Prompt / statement sources: ' + e(json.dumps(item["context_sources"])) + '</p></article>')
            body.append('</details>')
    if not inventory["urls"]:
        body.append('<p>No HTTP(S) URLs found in the selected records.</p>')
    body.append('</section>')
    # Keep the destination inventory ahead of potentially lengthy finding evidence.
    inventory_html = ''.join(body[inventory_start:])
    del body[inventory_start:]
    body.insert(inventory_position, inventory_html)
    unassigned = summary["unattributed_network"]
    body.append('<h2>Unattributed Network Observations</h2><p>HTTP: ' + e(unassigned["http"]) + ' &middot; HTTPS: ' + e(unassigned["https"]) + '. Imported observations need an exact, unique session and call ID match to count against a session.</p>')
    body.append('<h2>Coverage</h2><p>ATLAS ' + e(ATLAS_VERSION) + ' &middot; OWASP LLM Top 10 2026. Mappings are candidate classifications, not confirmed behavior.</p>')
    body.append(table(["OWASP category", "Loaded rules"], ['<tr><td>' + e(c["id"] + ' ' + c["name"]) + '</td><td>' + e(len(c["rule_ids"])) + '</td></tr>' for c in summary["classification"]["owasp_rule_coverage"]]))
    if summary["diagnostics"]:
        body.append('<h2>Input Diagnostics</h2><ul>' + ''.join('<li>' + e(json.dumps(d)) + '</li>' for d in summary["diagnostics"]) + '</ul>')
    body.append('<footer><p>Command and context excerpts are capped at 3,000 characters each; full finding records are in findings.jsonl. Session data is untrusted and may contain sensitive information despite best-effort redaction.</p><p><a href="summary.json">JSON summary</a> &middot; <a href="findings.jsonl">Findings</a> &middot; <a href="events.jsonl">Operations</a> &middot; <a href="http.jsonl">HTTP log</a> &middot; <a href="https.jsonl">HTTPS log</a></p></footer>')
    return '''<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'">
<title>''' + escape(APP_NAME, quote=True) + '''</title><style>
*{box-sizing:border-box}body{margin:0;background:#fff;color:#24282b;font:14px/1.55 system-ui,sans-serif;letter-spacing:0}main{max-width:1400px;margin:auto;padding:32px}h1{font-size:30px;margin:4px 0}h2{font-size:19px;margin:28px 0 12px;overflow-wrap:anywhere}h3{font-size:16px}h4{font-size:13px;margin-bottom:4px}a{color:#006d70;overflow-wrap:anywhere}p,li,td,code{overflow-wrap:anywhere}.eyebrow{font-size:12px;color:#006d70;font-weight:700}.muted,.definitions,footer{color:#596169}.metrics{display:grid;grid-template-columns:repeat(5,1fr);gap:20px;border-block:1px solid #d7dddf;padding:20px 0;margin:24px 0}.metrics strong{display:block;font-size:26px}.metrics span{display:block;font-size:12px}.notice{background:#fff3d9;border-left:4px solid #aa6500;padding:12px}.atlas-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(min(100%,180px),1fr));gap:8px}.atlas-cell{display:grid;grid-template-columns:1fr auto;grid-template-rows:auto 1fr;gap:6px;min-height:104px;padding:12px;border-radius:4px;text-decoration:none;overflow-wrap:anywhere}.atlas-cell:focus-visible{outline:3px solid #006d70;outline-offset:2px}.atlas-cell strong{grid-column:2;grid-row:1 / span 2;font-size:24px;line-height:1}.atlas-id{grid-column:1;font-size:12px;font-weight:700}.atlas-name{grid-column:1;align-self:end;font-size:13px;font-weight:600}.atlas-detail{border-bottom:1px solid #d7dddf}.atlas-detail ul{margin-top:4px}.table-scroll{overflow-x:auto}table{width:100%;border-collapse:collapse;text-align:left}th{font-size:12px;color:#50595d;background:#f2f5f5}th,td{padding:12px;border-bottom:1px solid #d7dddf;vertical-align:top}td:first-child{min-width:180px;max-width:360px}th:not(:first-child){min-width:80px}.flag{color:#a32432;font-weight:700}.clear{color:#226b52}.session{border-top:2px solid #d7dddf;margin-top:32px}details{margin:12px 0}summary{cursor:pointer;color:#006d70;font-weight:600;padding:8px 0}article{border-left:3px solid #bb4754;padding:0 16px;margin:24px 0}pre{white-space:pre-wrap;overflow-wrap:anywhere;background:#f4f6f6;padding:12px;font:12px/1.6 ui-monospace,monospace;max-height:320px;overflow:auto}footer{border-top:1px solid #d7dddf;margin-top:32px;padding-top:16px}@media(max-width:640px){main{padding:16px}.metrics{grid-template-columns:repeat(2,1fr);gap:16px}h1{font-size:25px}}@media print{main{padding:0}details>*,details{display:block}pre{max-height:none}.table-scroll{overflow:visible}body{font-size:10px}}
.timeline{list-style:none;margin:16px 0 24px;padding:0}.timeline li{display:grid;grid-template-columns:112px minmax(0,1fr);gap:14px;min-width:0}.timeline-time{display:block;padding:2px 0;font-size:12px;color:#596169;font-variant-numeric:tabular-nums}.timeline-time span{display:block}.timeline-entry{position:relative;min-width:0;border-left:2px solid #d7dddf;padding:0 0 18px 16px}.timeline-entry::before{content:"";position:absolute;left:-6px;top:5px;width:10px;height:10px;border-radius:50%;background:#757f82}.tone-alert .timeline-entry::before{background:#a32432}.tone-write .timeline-entry::before{background:#b76a16}.tone-network .timeline-entry::before{background:#006d70}.timeline-heading{display:flex;align-items:baseline;flex-wrap:wrap;gap:8px}.timeline-heading strong{font-size:13px}.timeline-heading code{font-size:11px;color:#596169}.timeline-signals{display:flex;gap:6px;flex-wrap:wrap;margin-top:5px}.signal{font-size:11px;font-weight:700}.signal-alert{color:#a32432}.signal-write{color:#935210}.signal-network{color:#006d70}.timeline-command{margin:6px 0 0;max-height:78px;background:#f4f6f6}.timeline-entry details{margin:2px 0 0}.timeline-entry details p{margin:8px 0}.timeline-entry details ul{margin:4px 0 10px;padding-left:20px}@media(max-width:640px){.timeline li{grid-template-columns:82px minmax(0,1fr);gap:8px}.timeline-time{font-size:11px}.timeline-entry{padding-left:12px}.timeline-command{font-size:11px}}
</style></head><body><main>''' + ''.join(body) + '</main></body></html>'


def url_info(url):
    try:
        parts = urlsplit(url)
        if parts.scheme.lower() not in {"http", "https"} or not parts.hostname:
            return None
        port = parts.port
        host = parts.hostname.rstrip(".")
        netloc = "[" + host + "]" if ":" in host else host
        if port is not None:
            netloc += ":" + str(port)
        return {"scheme": parts.scheme.lower(), "host": host, "port": port or (443 if parts.scheme.lower() == "https" else 80),
                "url": urlunsplit((parts.scheme.lower(), netloc, parts.path, "REDACTED" if parts.query else "", ""))}
    except ValueError:
        return None


def url_indicators(value):
    domains, urls = set(), set()
    for candidate in URL_RE.findall(value):
        info = url_info(candidate.rstrip(".,);]}"))
        if info:
            domains.add(info["host"])
            urls.add(info["url"])
    return sorted(domains), sorted(urls)


def redact_private_keys(value):
    parts, cursor = [], 0
    while match := PEM_BEGIN_RE.search(value, cursor):
        parts.append(value[cursor:match.start()])
        ending = re.compile(r"-----END " + re.escape(match.group(1)) + r"-----", re.I).search(value, match.end())
        parts.append("[REDACTED PRIVATE KEY]")
        if ending is None:
            return "".join(parts)
        cursor = ending.end()
    parts.append(value[cursor:])
    return "".join(parts)


def scrub(value, preserve_page=False):
    if isinstance(value, dict):
        return {k: scrub(v, preserve_page=k == "references") for k, v in value.items()}
    if isinstance(value, list):
        return [scrub(v, preserve_page=preserve_page) for v in value]
    if not isinstance(value, str):
        return value

    def redact_url(match):
        info = url_info(match.group())
        if not info:
            return "[invalid URL]"
        fragment = match.group().partition("#")[2]
        # Only numeric PDF page citations may survive in rule references.
        suffix = "#" + fragment if preserve_page and re.fullmatch(r"page=[1-9][0-9]*", fragment) else ""
        return info["url"] + suffix

    value = URL_RE.sub(redact_url, value)
    value = redact_private_keys(value)
    value = re.sub(r"(?i)(\b(?:proxy-)?authorization\s*:\s*aws4-hmac-sha256\s+)[^\r\n\"']+",
                   r"\1[REDACTED]", value)
    value = re.sub(r"(?i)(\b(?:proxy-)?authorization\s*:\s*)(?:basic|bearer|token|apikey)\s+[^\s\"']+",
                   r"\1[REDACTED]", value)
    value = re.sub(r"(?i)(bearer\s+)[^\s\"']+", r"\1[REDACTED]", value)
    value = re.sub(
        r"(?i)(?<![A-Za-z0-9_])((?:[A-Za-z][A-Za-z0-9]*_)*(?:api[_-]?key|access[_-]?key(?:_id)?|secret[_-]?access[_-]?key|session[_-]?token|client[_-]?secret|private[_-]?key|password|passwd|token|secret)\s*[=:]\s*)(?:\"[^\"\r\n]*\"|'[^'\r\n]*'|[^\s,;\"']+)",
        r"\1[REDACTED]", value)
    value = re.sub(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b", "[REDACTED AWS KEY ID]", value)
    return value


def run(args):
    rules = load_rules(args.rules)
    for index, literal in enumerate(getattr(args, "match", [])):
        if not literal:
            raise ValueError("--match requires a nonempty string")
        rules.append(Rule({"id": "cli-literal-" + str(index), "title": "User-supplied literal trigger",
            "level": "medium", "logsource": {"product": "codex", "category": "ai_session"},
            "detection": {"command": {"CommandLine|contains": literal},
                          "output": {"Output|contains": literal}, "condition": "command or output"}}))
    diagnostics = []
    roots = [Path(p).expanduser().resolve() for p in args.input] if args.input else [
        Path(args.codex_home).expanduser().resolve() / "sessions",
        Path(args.codex_home).expanduser().resolve() / "archived_sessions"]
    files = set()
    for root in roots:
        if root.is_file():
            files.add(root)
        elif root.is_dir():
            files.update(p.resolve() for p in root.rglob("*.jsonl") if p.is_file())
            for p in root.rglob("*.zst"):
                diagnostics.append({"file": str(p), "error": "compressed sessions unsupported; export JSONL first"})
        elif args.input:
            diagnostics.append({"file": str(root), "error": "input does not exist"})
    if not files:
        diagnostics.append({"error": "no session JSONL files found"})
    out = Path(args.output).expanduser().resolve()
    out.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    out.mkdir(mode=0o700, exist_ok=False)
    counts = {"files": len(files), "events": 0, "findings": 0, "http": 0, "https": 0,
              "file_write_operations": 0, "file_change_candidates": 0, "unresolved_file_calls": 0}
    classification_counts = {"atlas": {}, "owasp_llm": {}}
    sessions = {}
    session_files = []
    unattributed_network = {"http": 0, "https": 0}
    network_inventory = {}
    file_inventory, unresolved_file_calls = [], []
    handles = {}
    index = {}
    try:
        for name in ("events", "findings", "http", "https"):
            fd = os.open(out / (name + ".jsonl"), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            handles[name] = os.fdopen(fd, "w", encoding="utf-8")

        def emit(name, record):
            handles[name].write(json.dumps(scrub(record), ensure_ascii=True) + "\n")
            counts[name] += 1
            if name == "events":
                session = sessions[record["session_id"]]
                session["operations"] += 1
                if record["file_changes"]:
                    session["file_change_candidates"] += 1
                    counts["file_change_candidates"] += 1
                if record["file_write"]["candidate"]:
                    session["file_write_operations"] += 1
                    counts["file_write_operations"] += 1
                    if not record["file_changes"]:
                        session["unresolved_file_calls"] += 1
                        counts["unresolved_file_calls"] += 1
            elif name == "findings":
                event = record["event"]
                session = sessions[event["session_id"]]
                detection = session["detections"].setdefault(record["rule_id"], {
                    "rule_id": record["rule_id"], "title": record["title"], "level": record["level"], "count": 0})
                detection["count"] += 1
                finding = {key: record[key] for key in ("rule_id", "rule_file", "title", "level", "classification", "investigation")}
                finding.update({"call_id": event["call_id"], "source": event["source"],
                                "result_source": event.get("result_source")})
                for target, field in (("command", "CommandLine"), ("user_request", "UserRequest"),
                                      ("assistant_context", "AssistantContext"), ("justification", "Justification"), ("output", "Output")):
                    value = scrub(event[field])
                    finding[target] = value[:3000] + ("\n[excerpt truncated]" if len(value) > 3000 else "")
                session["findings"].append(finding)
            elif name in {"http", "https"}:
                add_network_item(network_inventory, record)
                session = sessions.get(str(record.get("session_id")))
                if record["evidence_type"] == "session_url_reference" and session is not None:
                    session["network"][name + "_references"] += 1
                elif record.get("correlation") == "exact_session_and_call_id" and session is not None:
                    session["network"][name + "_observations"] += 1
                else:
                    unattributed_network[name] += 1

        def detect(event, observed_only=False):
            for rule in rules:
                if observed_only and not rule.matches_observed_network:
                    continue
                matched, selections = rule.match(event)
                if not matched:
                    continue
                for field, totals in classification_counts.items():
                    for mapping in rule.classification[field]:
                        totals[mapping["id"]] = totals.get(mapping["id"], 0) + 1
                emit("findings", {"rule_id": rule.raw["id"], "title": rule.raw["title"],
                                  "rule_file": getattr(rule, "source_file", None),
                                  "level": rule.raw["level"], "matched_selections": selections,
                                  "status": rule.raw.get("status", "experimental"),
                                  "description": rule.raw.get("description", ""),
                                  "references": rule.raw.get("references", []),
                                  "classification": rule.classification,
                                  "intelligence": rule.raw.get("intelligence", {}),
                                  "evidence_scope": rule.raw.get("evidence_scope", "recorded_tool_call"),
                                  "investigation": rule.raw.get("investigation", "Review the command and recorded context."),
                                  "falsepositives": rule.raw.get("falsepositives", []), "event": event})

        for path in sorted(files):
            file_info = {"path": str(path), "size_bytes": None, "created_at": None,
                         "modified_at": None, "sha1": None, "hashed_bytes": 0}
            events = parse_session(path, diagnostics, sessions, file_info)
            session_files.append(file_info)
            if not events:
                diagnostics.append({"file": str(path), "error": "no supported tool calls found; coverage may be incomplete"})
            for event in events:
                event["file_write"] = file_write_indicators(event)
                event["file_changes"] = file_change_candidates(event)
                emit("events", event)
                for change in event["file_changes"]:
                    file_inventory.append({**change, "session_id": event["session_id"],
                                           "call_id": event["call_id"], "cwd": event["Cwd"],
                                           "source": event["source"],
                                           "execution_status": event["execution_status"]})
                if event["file_write"]["candidate"] and not event["file_changes"]:
                    unresolved_file_calls.append({"session_id": event["session_id"],
                        "call_id": event["call_id"], "source": event["source"],
                        "reasons": event["file_write"]["reasons"]})
                key = (event["session_id"], event["call_id"])
                if event["call_id"]:
                    # Ambiguous IDs must not create a false context association.
                    index[key] = None if key in index else {k: event[k] for k in ("source", "context_sources", "ToolName", "CommandLine", "UserRequest", "AssistantContext", "Justification")}
                detect(event)
                for field in ("CommandLine", "Output", "UserRequest", "AssistantContext", "Justification"):
                    for url in sorted(set(URL_RE.findall(event[field]))):
                        info = url_info(url.rstrip(".,);]}"))
                        if info:
                            ref_source = event["source"]
                            if field == "Output":
                                ref_source = event.get("result_source", ref_source)
                            elif field in {"UserRequest", "AssistantContext"}:
                                context = event["context_sources"]["user_request" if field == "UserRequest" else "assistant_statement"]
                                if context:
                                    ref_source = context["source"]
                            emit(info["scheme"], {**info, "evidence_type": "session_url_reference",
                                 "traffic_confirmed": False, "field": field, "session_id": event["session_id"],
                                 "call_id": event["call_id"], "source": ref_source,
                                 "context": {k: event[k] for k in ("source", "context_sources", "ToolName", "CommandLine", "UserRequest", "AssistantContext", "Justification")}})
        for network_path in args.network_log:
            for line, record, digest in records(Path(network_path).expanduser().resolve(), diagnostics):
                info = url_info(record.get("url", "")) if isinstance(record.get("url"), str) else None
                if not info:
                    diagnostics.append({"file": network_path, "line": line, "error": "network record requires an HTTP(S) url"})
                    continue
                session_id, call_id = record.get("session_id"), record.get("call_id")
                context = index.get((session_id, call_id)) if isinstance(session_id, str) and isinstance(call_id, str) else None
                emit(info["scheme"], {**info, "evidence_type": "imported_network_observation",
                     "traffic_confirmed": "reported_by_input_log", "timestamp": record.get("timestamp"),
                     "method": record.get("method"), "status": record.get("status"),
                     "session_id": session_id, "call_id": call_id, "context": context,
                     "correlation": "exact_session_and_call_id" if context else "unattributed",
                     "source": {"file": str(Path(network_path).resolve()), "line": line, "sha256": digest}})
                if context:
                    observed_event = {
                        "EventType": "network_observation", "session_id": session_id,
                        "call_id": call_id, "ToolName": "network_log", "CommandLine": "",
                        "CommandDomains": [], "CommandURLs": [], "OutputDomains": [], "OutputURLs": [],
                        "ObservedDomains": [info["host"]], "ObservedURLs": [info["url"]],
                        "UserRequest": context["UserRequest"], "AssistantContext": context["AssistantContext"],
                        "Justification": context["Justification"], "Output": "", "Cwd": "",
                        "SandboxPermissions": "", "ContextMissing": not bool(context["UserRequest"]),
                        "source": {"file": str(Path(network_path).resolve()), "line": line,
                                   "sha256": digest, "timestamp": record.get("timestamp")},
                        "parent_source": context["source"],
                        "context_sources": context["context_sources"],
                        "execution_status": "reported_by_input_log",
                        "intent_assessment": "Imported observation; request time and actual intent unverified.",
                        "file_write": {"candidate": False, "reasons": [], "patch_targets": []}}
                    detect(observed_event, observed_only=True)
    finally:
        for handle in handles.values():
            handle.close()
    if not args.input:
        try:
            local_computer, local_user = socket.gethostname(), getpass.getuser()
        except (OSError, KeyError):
            local_computer = local_user = None
        for session in sessions.values():
            if session["computer_name_source"] is None:
                set_session_identity(session, "computer_name", local_computer, "local_codex_store")
            if session["user_name_source"] is None:
                set_session_identity(session, "user_name", local_user, "local_codex_store")
    timelines = session_timelines(out)
    for session_id, session in sessions.items():
        session["timeline"] = timelines.get(session_id, [])
        session["detections"] = list(session["detections"].values())
        session["has_detections"] = bool(session["findings"])
        session["network_items"] = sum(session["network"].values())
    counts["sessions"] = len(sessions)
    destinations = sorted(network_inventory.values(), key=lambda item: (item["domain"], item["url"]))
    domains = {}
    for destination in destinations:
        domain = domains.setdefault(destination["domain"], {
            "domain": destination["domain"], "url_count": 0, "references": 0, "observations": 0})
        domain["url_count"] += 1
        domain["references"] += destination["references"]
        domain["observations"] += destination["observations"]
    counts["sessions_with_detections"] = sum(s["has_detections"] for s in sessions.values())
    summary = {"version": VERSION, "generated_at": datetime.now(timezone.utc).isoformat(),
               "counts": counts, "rules": len(rules), "partial": bool(diagnostics), "diagnostics": diagnostics,
               "sessions": list(sessions.values()), "unattributed_network": unattributed_network,
               "session_files": session_files,
               "file_inventory": file_inventory,
               "unresolved_file_calls": unresolved_file_calls,
               "network_inventory": {"domains": list(domains.values()), "urls": destinations},
               "counting_basis": {"sessions": "Distinct IDs from readable rollout records; missing IDs use the source path.",
                                  "identity": "Explicit session metadata takes priority. For default local Codex stores, missing computer/user names identify the analysis computer and account, not independently verified session origin. Imported files without explicit metadata remain unknown.",
                                  "operations": "Recorded supported tool-call records, including denied calls; nested calls are not expanded.",
                                  "file_writes": "Tool calls with lexical write indicators, not successful writes or distinct files.",
                                  "file_inventory": "Recorded patch declarations and selected command targets; file paths and operations are candidates, not confirmed filesystem changes. Unresolved write calls are counted separately.",
                                  "network": "URL references plus imported observations; these are separate evidence types, not unique requests.",
                                  "duplicates": "Files with the same session ID are grouped; duplicate records across files remain counted."},
               "classification": classification_summary(rules, classification_counts),
               "limits": ["No packet capture or TLS decryption; URL references do not prove traffic.",
                          "Recorded context does not prove intent, authorization, or execution success.",
                          "Redaction is best effort; reports may contain sensitive session data."]}
    summary = scrub(summary)
    fd = os.open(out / "summary.json", os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as stream:
        json.dump(summary, stream, indent=2)
    fd = os.open(out / "report.html", os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as stream:
        stream.write(render_html(summary))
    print(json.dumps({"output": str(out), **counts, "partial": bool(diagnostics)}, indent=2))
    return 2 if diagnostics else 0


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", action="append", default=[], help="Session JSONL file or directory; repeatable")
    parser.add_argument("--codex-home", default=os.environ.get("CODEX_HOME", str(Path.home() / ".codex")))
    parser.add_argument("--output", default=str(Path.home() / "codex-analysis-reports" /
        ("codex-analysis-" + datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ"))),
        help="New report directory (default: ~/codex-analysis-reports; must not exist)")
    parser.add_argument("--rules", action="append", default=[], help="Additional detection file or directory; one detection per file")
    parser.add_argument("--match", action="append", default=[], help="Additional literal command/output trigger; repeatable")
    parser.add_argument("--network-log", action="append", default=[], help="Normalized HTTP(S) observation JSONL")
    args = parser.parse_args()
    print("\n" + ASCII_BANNER + "\n\n" + APP_NAME + "\n", file=sys.stderr, flush=True)
    try:
        return run(args)
    except (OSError, ValueError, TypeError, re.error) as exc:
        print("codex-analysis: " + str(exc), file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
