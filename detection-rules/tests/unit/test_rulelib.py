from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))

from rulelib import (  # noqa: E402
    evaluate_fixture,
    evaluate_kql,
    load_json,
    load_metadata,
    parse_kql,
)


class RuleLibraryTests(unittest.TestCase):
    def test_boolean_and_wildcard_kql(self) -> None:
        event = {
            "watchmyai": {"resource": {"path": {"restricted": True}}},
            "event": {"action": "decision.created"},
        }
        query = 'watchmyai.resource.path.restricted:true and event.action:"decision.created"'
        self.assertTrue(evaluate_kql(parse_kql(query), event))

    def test_threshold_boundary(self) -> None:
        rule = next(rule for rule in load_metadata() if rule["rule_id"] == "WMAI-023")
        malicious = load_json(ROOT / rule["fixtures"]["malicious"])
        benign = load_json(ROOT / rule["fixtures"]["benign"])
        self.assertTrue(evaluate_fixture(rule, malicious))
        self.assertFalse(evaluate_fixture(rule, benign))


if __name__ == "__main__":
    unittest.main()
