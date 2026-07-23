from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))

import validate  # noqa: E402


class SchemaTests(unittest.TestCase):
    def test_all_metadata_conforms(self) -> None:
        result = validate.Validation()
        validate.validate_gateway_contract(result)
        rules = validate.validate_metadata(result)
        self.assertEqual(len(rules), 20)
        self.assertEqual(result.errors, [])

    def test_all_elastic_definitions_conform(self) -> None:
        result = validate.Validation()
        rules = validate.validate_metadata(result)
        validate.validate_elastic(result, rules)
        self.assertEqual(result.errors, [])


if __name__ == "__main__":
    unittest.main()
