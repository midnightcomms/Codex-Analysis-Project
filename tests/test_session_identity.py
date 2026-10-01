"""Computer/user attribution must distinguish recorded facts from local fallback."""
import contextlib
import importlib.util
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("codex_analysis", ROOT / "codex-analysis.py")
app = importlib.util.module_from_spec(spec)
spec.loader.exec_module(app)


def rollout(path, session_id, **metadata):
    rows = [
        {"type": "session_meta", "payload": {"id": session_id, **metadata}},
        {"type": "response_item", "payload": {"type": "function_call", "name": "exec_command",
                                               "call_id": "call-1", "arguments": '{"cmd":"pwd"}'}},
    ]
    path.write_text("".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8")


def analyze(root, input_files):
    args = app.argparse.Namespace(input=input_files, codex_home=str(root / "codex-home"),
                                  rules=[], network_log=[], match=[], output=str(root / "report"))
    with contextlib.redirect_stdout(io.StringIO()):
        app.run(args)
    summary = json.loads((root / "report/summary.json").read_text())
    html = (root / "report/report.html").read_text()
    return summary["sessions"][0], html


class SessionIdentityTests(unittest.TestCase):
    def test_explicit_identity_in_imported_rollout(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "session.jsonl"
            rollout(source, "session-1", hostname="recorded-host", username="recorded-user")
            session, html = analyze(root, [str(source)])
            self.assertEqual(session["computer_name"], "recorded-host")
            self.assertEqual(session["user_name"], "recorded-user")
            self.assertEqual(session["computer_name_source"], "session_metadata:hostname")
            self.assertIn("recorded-host", html)
            self.assertIn("recorded-user", html)

    def test_imported_rollout_without_identity_is_unknown(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "session.jsonl"
            rollout(source, "session-1", cwd="/example/possible-user/project")
            session, html = analyze(root, [str(source)])
            self.assertIsNone(session["computer_name"])
            self.assertIsNone(session["user_name"])
            self.assertIn("Unknown", html)

    def test_default_local_store_fallback_is_labeled(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            sessions = root / "codex-home/sessions"
            sessions.mkdir(parents=True)
            rollout(sessions / "session.jsonl", "session-1")
            with patch.object(app.socket, "gethostname", return_value="analysis-box"), \
                 patch.object(app.getpass, "getuser", return_value="analyst"):
                session, html = analyze(root, [])
            self.assertEqual(session["computer_name"], "analysis-box")
            self.assertEqual(session["user_name"], "analyst")
            self.assertEqual(session["computer_name_source"], "local_codex_store")
            self.assertIn("local_codex_store", html)

    def test_conflicting_metadata_is_not_replaced_by_local_fallback(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            sessions = root / "codex-home/sessions"
            sessions.mkdir(parents=True)
            rollout(sessions / "one.jsonl", "session-1", hostname="box-one")
            rollout(sessions / "two.jsonl", "session-1", hostname="box-two")
            with patch.object(app.socket, "gethostname", return_value="analysis-box"), \
                 patch.object(app.getpass, "getuser", return_value="analyst"):
                session, _ = analyze(root, [])
            self.assertIsNone(session["computer_name"])
            self.assertEqual(session["computer_name_source"], "conflicting_session_metadata")


if __name__ == "__main__":
    unittest.main()
