from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
REPOSITORY_ROOT = ROOT.parent


class PackagingIntegrationTests(unittest.TestCase):
    def test_package_contains_exact_disabled_deployable_rule_set(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory)
            result = subprocess.run(
                [
                    sys.executable,
                    "scripts/package_rules.py",
                    "--skip-validation",
                    "--output-dir",
                    str(output),
                ],
                cwd=ROOT,
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            ndjson = output / "watchmyai-rules.ndjson"
            lines = ndjson.read_text(encoding="utf-8").splitlines()
            rules = [json.loads(line) for line in lines]
            manifest = json.loads((output / "watchmyai-package-manifest.json").read_text(encoding="utf-8"))
            self.assertEqual(len(rules), 20)
            self.assertEqual([item["rule_id"] for item in rules], manifest["rule_ids"])
            self.assertTrue(all(item["enabled"] is False for item in rules))
            self.assertEqual(manifest["project"], "WatchMyAI")
            self.assertEqual(manifest["package_type"], "elastic-detection-rule-deployment")
            self.assertEqual(manifest["rule_count"], 20)
            self.assertEqual(manifest["deferred_research_rule_count"], 45)
            self.assertEqual(manifest["telemetry_schema_version"], "1.1.0")
            self.assertEqual(manifest["elastic_validated_version"], "9.4.3")
            self.assertEqual(manifest["ndjson_sha256"], hashlib.sha256(ndjson.read_bytes()).hexdigest())

    def test_checksum_file_verifies_package_outputs(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory)
            result = subprocess.run(
                [sys.executable, "scripts/package_rules.py", "--skip-validation", "--output-dir", directory],
                cwd=ROOT,
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            for line in (output / "SHA256SUMS.txt").read_text(encoding="ascii").splitlines():
                expected, name = line.split("  ", 1)
                self.assertEqual(hashlib.sha256((output / name).read_bytes()).hexdigest(), expected)

    def test_package_build_is_reproducible(self) -> None:
        with tempfile.TemporaryDirectory() as first, tempfile.TemporaryDirectory() as second:
            for output in (first, second):
                result = subprocess.run(
                    [sys.executable, "scripts/package_rules.py", "--skip-validation", "--output-dir", output],
                    cwd=ROOT,
                    capture_output=True,
                    text=True,
                    check=False,
                )
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            for name in ("watchmyai-rules.ndjson", "watchmyai-package-manifest.json", "SHA256SUMS.txt"):
                self.assertEqual((Path(first) / name).read_bytes(), (Path(second) / name).read_bytes())

    def test_root_import_dry_run_needs_no_api_key(self) -> None:
        environment = os.environ.copy()
        environment.pop("ELASTIC_API_KEY", None)
        result = subprocess.run(
            [sys.executable, "scripts/import/import_rules.py", "--dry-run"],
            cwd=REPOSITORY_ROOT,
            env=environment,
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("DRY RUN", result.stdout)


if __name__ == "__main__":
    unittest.main()
