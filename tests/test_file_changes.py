"""File inventory records declared targets, not observed filesystem effects."""
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


class FileChangeTests(unittest.TestCase):
    def changes(self, command, tool="exec_command"):
        return {(item["operation"], item["path"]) for item in
                app.file_change_candidates({"ToolName": tool, "CommandLine": command})}

    def test_patch_add_update_delete_and_move(self):
        command = "*** Begin Patch\n*** Add File: new.txt\n+text\n*** Update File: old.txt\n@@\n-old\n+new\n*** Delete File: gone.txt\n*** Update File: from.txt\n*** Move to: to.txt\n*** End Patch"
        self.assertEqual(self.changes(command, "apply_patch"), {
            ("created", "new.txt"), ("modified", "old.txt"), ("deleted", "gone.txt"),
            ("deleted", "from.txt"), ("created", "to.txt")})
        wrapped = 'text(await tools.apply_patch("*** Begin Patch\\n*** Delete File: obsolete.txt\\n*** End Patch"))'
        self.assertIn(("deleted", "obsolete.txt"), self.changes(wrapped, "exec"))
        outer = "*** Begin Patch\n*** Add File: test.py\n+example = '*** Delete File: not-real.txt'\n*** End Patch"
        wrapped_outer = "text(await tools.apply_patch(" + json.dumps(outer) + "))"
        self.assertEqual(self.changes(wrapped_outer, "exec"), {("created", "test.py")})
        variable_patch = "const patch=" + json.dumps(outer) + "; text(await tools.apply_patch(patch))"
        self.assertEqual(self.changes(variable_patch, "exec"), {("created", "test.py")})

    def test_shell_targets_and_ambiguous_creates(self):
        self.assertIn(("created_or_modified", "out.txt"), self.changes("printf text > out.txt"))
        self.assertEqual(self.changes("rm -f old.txt"), {("deleted", "old.txt")})
        self.assertEqual(self.changes("touch first.txt second.txt"), {
            ("created_or_modified", "first.txt"), ("created_or_modified", "second.txt")})
        self.assertIn(("created_or_modified", "download.bin"), self.changes("curl -o download.bin https://example.test"))
        self.assertIn(("created", "exclusive.txt"), self.changes("python3 -c \"open('exclusive.txt', 'x').close()\""))
        self.assertIn(("created_or_modified", "written.txt"), self.changes("python3 -c \"Path('written.txt').write_text('x')\""))
        self.assertFalse(self.changes("rg \"Path('written.txt').write_text\" ."))

    def test_nested_exec_command_and_no_false_delete_from_redirect(self):
        wrapper = 'text(await tools.exec_command({cmd:"rm -f old.txt > command.log"}))'
        self.assertEqual(self.changes(wrapper, "exec"), {
            ("deleted", "old.txt"), ("created_or_modified", "command.log")})
        self.assertFalse(self.changes('text(await tools.web__run({search_query:[{q:"rm old.txt"}]}))', "exec"))

    def test_report_sections_link_back_to_calls(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            commands = [
                "*** Begin Patch\n*** Add File: new.txt\n+x\n*** Update File: changed.txt\n@@\n-a\n+b\n*** Delete File: removed.txt\n*** End Patch",
                "printf text > maybe.txt",
                "Path('unresolved').write_text(variable)",
            ]
            records = [{"type": "session_meta", "payload": {"id": "files-session"}}]
            for index, command in enumerate(commands):
                records.append({"type": "response_item", "payload": {"type": "function_call",
                    "name": "apply_patch" if index == 0 else "exec_command", "call_id": "call-" + str(index),
                    "arguments": json.dumps({"cmd": command})}})
            source = root / "session.jsonl"
            source.write_text("".join(json.dumps(record) + "\n" for record in records))
            args = app.argparse.Namespace(input=[str(source)], codex_home="unused", rules=[],
                network_log=[], match=[], output=str(root / "report"))
            with contextlib.redirect_stdout(io.StringIO()):
                app.run(args)
            summary = json.loads((root / "report/summary.json").read_text())
            page = (root / "report/report.html").read_text()
            self.assertEqual({(item["operation"], item["path"]) for item in summary["file_inventory"]}, {
                ("created", "new.txt"), ("modified", "changed.txt"), ("deleted", "removed.txt"),
                ("created_or_modified", "maybe.txt")})
            self.assertEqual(summary["counts"]["file_change_candidates"], 2)
            self.assertEqual(summary["counts"]["unresolved_file_calls"], 1)
            self.assertIn('id="file-changes"', page)
            self.assertIn('href="#call-0-', page)
            self.assertIn("Unresolved write targets (1)", page)
            self.assertIn("removed.txt", page)


if __name__ == "__main__":
    unittest.main()
