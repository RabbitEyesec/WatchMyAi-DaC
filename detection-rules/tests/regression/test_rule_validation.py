from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))

import validate  # noqa: E402
from rulelib import evaluate_fixture, load_json, load_metadata, parse_kql  # noqa: E402


class RuleRegressionTests(unittest.TestCase):
    def test_repository_validation(self) -> None:
        self.assertEqual(validate.main(), 0)

    def test_all_rules_are_packageable_and_disabled(self) -> None:
        rules = load_metadata()
        self.assertEqual(len(rules), 20)
        self.assertTrue(all(rule["deployment"]["packageable"] for rule in rules))
        self.assertTrue(all(rule["elastic"]["enabled"] is False for rule in rules))

    def test_every_malicious_fixture_matches(self) -> None:
        for rule in load_metadata():
            with self.subTest(rule=rule["rule_id"]):
                fixture = load_json(ROOT / rule["fixtures"]["malicious"])
                self.assertTrue(evaluate_fixture(rule, fixture))

    def test_every_benign_fixture_does_not_match(self) -> None:
        for rule in load_metadata():
            with self.subTest(rule=rule["rule_id"]):
                fixture = load_json(ROOT / rule["fixtures"]["benign"])
                self.assertFalse(evaluate_fixture(rule, fixture))

    def test_malformed_kql_is_rejected(self) -> None:
        with self.assertRaises(ValueError):
            parse_kql('event.category:process and (process.name:"ssh"')

    def test_no_circular_producer_findings(self) -> None:
        for rule in load_metadata():
            self.assertNotIn("event.dataset_name", rule["elastic"]["query"])


if __name__ == "__main__":
    unittest.main()
