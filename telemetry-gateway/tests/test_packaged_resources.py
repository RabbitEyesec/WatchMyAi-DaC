from __future__ import annotations

import os
from importlib import resources
from pathlib import Path

from watchmyai.cli.main import main
from watchmyai.discovery.signatures import SignatureCatalog


def test_runtime_resources_are_packaged(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(Path, "home", lambda: tmp_path)
    package = resources.files("watchmyai.resources")
    for name in ("agent_signatures.yml", "redaction.yml", "policy-bundle.yml"):
        assert package.joinpath(name).read_text(encoding="utf-8").strip()
    assert SignatureCatalog.load_default().signatures
    assert main(["--home", str(tmp_path / "absent-home"), "self-check"]) == 0


def test_init_copies_private_runtime_resources(tmp_path) -> None:
    home = tmp_path / "watchmyai-home"
    assert main(["--home", str(home), "init"]) == 0
    for name in ("config.yml", "agent_signatures.yml", "redaction.yml", "policy-bundle.yml"):
        path = home / name
        assert path.is_file()
        if os.name != "nt":
            assert path.stat().st_mode & 0o077 == 0
    if os.name != "nt":
        assert home.stat().st_mode & 0o077 == 0
