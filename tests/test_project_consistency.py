from scripts.validate.validate_project import validate


def test_unified_project_contract() -> None:
    assert validate() == []
