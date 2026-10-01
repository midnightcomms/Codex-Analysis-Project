"""Offline tests for structured URL indicators and correlated network rules."""
import contextlib
import importlib.util
import io
import json
from pathlib import Path
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("codex_analysis", ROOT / "codex-analysis.py")
app = importlib.util.module_from_spec(spec)
spec.loader.exec_module(app)
PACK = ROOT / "rules/domain-intelligence"


class DomainIntelligenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.rules = {rule.raw["id"]: rule for rule in app.load_rules([str(PACK)])
                   if rule.raw["id"].startswith("fakeagent-")}

    def test_every_ioc_exactness_and_source(self):
        cases = {
            "fakeagent-redirect-domain": ("https://claude.ai.download-app.us/start", "https://claude.ai/download-app.us/start"),
            "fakeagent-installer-url": ("https://downloading-api.it.com/html/claude/win", "https://downloading-api.it.com/html/claude/linux"),
            "fakeagent-backup-c2-domain": ("https://5ca8758c-02d0-4a72-89c8-d468b66dda41.com/check", "https://not-5ca8758c-02d0-4a72-89c8-d468b66dda41.com/check"),
            "fakeagent-c2-ip": ("http://2.24.131.246/ping", "http://2.24.131.247/ping"),
            "fakeagent-artifact-url": ("https://claude.ai/public/artifacts/ca456f1f-44c0-42af-b329-4f1c7534a877", "https://claude.ai/public/artifacts/other"),
        }
        self.assertEqual(set(cases), set(self.rules))
        for key, (positive, negative) in cases.items():
            with self.subTest(rule=key):
                rule = self.rules[key]
                self.assertEqual(rule.raw["intelligence"]["date"], "2026-07-22")
                for field in ("Command", "Observed"):
                    domains, urls = app.url_indicators(positive)
                    self.assertTrue(rule.match({field + "Domains": domains, field + "URLs": urls})[0])
                    domains, urls = app.url_indicators(negative)
                    self.assertFalse(rule.match({field + "Domains": domains, field + "URLs": urls})[0])
                self.assertFalse(rule.match({"UserRequest": positive, "Output": positive})[0])

    def test_url_fields_and_array_matcher(self):
        domains, urls = app.url_indicators("open HTTPS://EXAMPLE.COM/a?secret=value and https://other.test/b#frag")
        self.assertEqual(domains, ["example.com", "other.test"])
        self.assertEqual(urls, ["https://example.com/a?REDACTED", "https://other.test/b"])
        self.assertTrue(app.field_test("CommandDomains", ["missing.test", "other.test"])({"CommandDomains": domains}))
        self.assertTrue(app.field_test("CommandDomains|all", ["example.com", "other.test"])({"CommandDomains": domains}))
        self.assertFalse(app.field_test("CommandDomains|all", ["example.com", "missing.test"])({"CommandDomains": domains}))
        self.assertTrue(app.field_test("CommandLine|contains", "abc")({"CommandLine": "ABC"}))

    def test_report_matches_command_and_only_exactly_correlated_observation(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            records = [
                {"type": "session_meta", "payload": {"id": "ioc-session"}},
                {"type": "response_item", "payload": {"type": "message", "role": "user", "content": "Inspect these endpoints."}},
                {"type": "response_item", "payload": {"type": "function_call", "name": "exec_command", "call_id": "one", "arguments": json.dumps({"cmd": "curl https://claude.ai.download-app.us/start"})}},
                {"type": "response_item", "payload": {"type": "function_call", "name": "exec_command", "call_id": "two", "arguments": json.dumps({"cmd": "printf 'hello'"})}},
            ]
            source = root / "session.jsonl"
            source.write_text("".join(json.dumps(record) + "\n" for record in records))
            network = root / "network.jsonl"
            observations = [
                {"url": "https://downloading-api.it.com/html/claude/win", "session_id": "ioc-session", "call_id": "two"},
                {"url": "https://2.24.131.246/ping", "session_id": "ioc-session", "call_id": "missing"},
            ]
            network.write_text("".join(json.dumps(record) + "\n" for record in observations))
            args = app.argparse.Namespace(input=[str(source)], codex_home="unused", rules=[str(PACK)],
                                          network_log=[str(network)], match=[], output=str(root / "out"))
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(app.run(args), 0)
            findings = [json.loads(line) for line in (root / "out/findings.jsonl").read_text().splitlines()]
            pairs = {(finding["rule_id"], finding["event"]["EventType"]) for finding in findings}
            self.assertIn(("fakeagent-redirect-domain", "tool_call"), pairs)
            self.assertIn(("fakeagent-installer-url", "network_observation"), pairs)
            self.assertNotIn("fakeagent-c2-ip", {finding["rule_id"] for finding in findings})
            observed = next(finding for finding in findings if finding["rule_id"] == "fakeagent-installer-url")
            self.assertEqual(observed["event"]["parent_source"]["file"], str(source))
            summary = json.loads((root / "out/summary.json").read_text())
            self.assertEqual(summary["counts"]["findings"], len(findings))
            self.assertIn("FakeAgent Claude Desktop installer URL", (root / "out/report.html").read_text())


if __name__ == "__main__":
    unittest.main()
