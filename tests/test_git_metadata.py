"""Tests for Git commit / PR attribution hygiene."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import check_git_metadata as meta  # noqa: E402


class GitMetadataTests(unittest.TestCase):
    def test_clean_conventional_commit(self) -> None:
        msg = "feat: add network broker probe\n\nImplement Owner-gated dry-run path.\n"
        self.assertEqual(meta.find_violations(msg), [])

    def test_forbidden_coauthor_trailer(self) -> None:
        msg = "fix: x\n\nCo-authored-by: Cursor <cursoragent@cursor.com>\n"
        hits = meta.find_violations(msg)
        self.assertTrue(hits)
        self.assertIn("Co-authored-by: Cursor", hits[0])

    def test_forbidden_made_with_trailer(self) -> None:
        msg = "chore: docs\n\nMade-with: Cursor\n"
        self.assertTrue(meta.find_violations(msg))

    def test_forbidden_pr_marketing_footer(self) -> None:
        body = "## Summary\n- x\n\nMade with Cursor\n"
        self.assertTrue(meta.find_violations(body))

    def test_forbidden_markdown_linked_footer(self) -> None:
        body = "Merge strategy: Merge commit (no squash/rebase)\n\nMade with [Cursor](https://cursor.com)\n"
        self.assertTrue(meta.find_violations(body))

    def test_case_and_whitespace_variations(self) -> None:
        self.assertTrue(meta.find_violations("  MADE WITH   Cursor  \n"))
        self.assertTrue(meta.find_violations("co-authored-by: cursor <x@y.z>\n"))

    def test_legitimate_cursor_acp_reference(self) -> None:
        msg = "feat: wire Cursor ACP runtime smoke path\n\nKeep live Cursor ACP blocked.\n"
        self.assertEqual(meta.find_violations(msg), [])

    def test_quoted_example_in_fenced_code_ignored(self) -> None:
        body = (
            "Notes:\n\n"
            "```\n"
            "Co-authored-by: Cursor <cursoragent@cursor.com>\n"
            "Made with [Cursor](https://cursor.com)\n"
            "```\n"
            "\nMerge strategy: Merge commit (no squash/rebase)\n"
        )
        self.assertEqual(meta.find_violations(body), [])

    def test_merge_commit_without_attribution(self) -> None:
        msg = "Merge pull request #21 from sergio-tr/refactor/eos-solid-architecture\n"
        self.assertEqual(meta.find_violations(msg), [])

    def test_cli_accepts_clean_pr_body_file(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "body.md"
            path.write_text(
                "## Summary\n- clean\n\nMerge strategy: Merge commit (no squash/rebase)\n",
                encoding="utf-8",
            )
            self.assertEqual(meta.main(["--pr-body-file", str(path)]), 0)

    def test_cli_rejects_dirty_pr_body_file(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "body.md"
            path.write_text("x\n\nMade with [Cursor](https://cursor.com)\n", encoding="utf-8")
            self.assertEqual(meta.main(["--pr-body-file", str(path)]), 1)


if __name__ == "__main__":
    unittest.main()
