from __future__ import annotations

from pathlib import Path

from pytest import CaptureFixture

from watchmyai.cli.main import EXIT_VALIDATION, main


def test_invalid_signed_root_reports_sanitized_error(tmp_path: Path, capsys: CaptureFixture[str]) -> None:
    root = tmp_path / "invalid-root.json"
    root.write_text('{"signed":', "utf-8")

    result = main(
        [
            "--home",
            str(tmp_path / "runtime"),
            "policy",
            "enroll-root",
            str(root),
            "--organization-id",
            "org-test",
        ]
    )

    captured = capsys.readouterr()
    assert result == EXIT_VALIDATION
    assert captured.out == ""
    assert "signed policy operation rejected (INVALID_METADATA_JSON)" in captured.err
    assert "Traceback" not in captured.err
    assert str(root) not in captured.err


def test_signed_setup_requires_explicit_rule_enablement(tmp_path: Path, capsys: CaptureFixture[str]) -> None:
    result = main(
        [
            "setup",
            "--signed-root",
            str(tmp_path / "root.json"),
            "--signed-policy-release",
            str(tmp_path / "release"),
            "--organization-id",
            "org-test",
        ]
    )

    captured = capsys.readouterr()
    assert result == 3
    assert "requires --enable-rules" in captured.err
    assert "Traceback" not in captured.err
