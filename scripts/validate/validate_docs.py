#!/usr/bin/env python3
"""Validate Markdown links, headings, fences, and documentation image assets."""

from __future__ import annotations

import re
import sys
from collections import Counter
from pathlib import Path
from urllib.parse import unquote, urlsplit

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))

from utilities.build_source_archive import release_files  # noqa: E402

IMAGE_SUFFIXES = {".png", ".jpg", ".jpeg", ".webp", ".svg", ".gif"}
LINK_RE = re.compile(r"(!?)\[[^\]]*\]\((<[^>]+>|[^)\s]+)(?:\s+['\"][^'\"]*['\"])?\)")
HEADING_RE = re.compile(r"^(#{1,6})\s+(.+?)\s*$")
FENCE_RE = re.compile(r"^\s*(`{3,}|~{3,})([^`]*)$")
PERSONAL_PATH_RE = re.compile(r"(?:/Users/[^/\s]+|[A-Za-z]:\\Users\\[^\\\s]+)")
FORBIDDEN_IMAGE_NAME_RE = re.compile(
    r"(?:^screenshot(?:[\s_-]|$)|^image\d|final[-_ ]final|\s)", re.IGNORECASE
)


def markdown_files() -> list[Path]:
    return [path for path in release_files(ROOT) if path.suffix == ".md"]


def image_files() -> list[Path]:
    return [path for path in release_files(ROOT) if path.suffix.lower() in IMAGE_SUFFIXES]


def has_exact_case(path: Path) -> bool:
    """Return whether every repository-relative path component matches disk casing."""
    try:
        relative = path.relative_to(ROOT)
    except ValueError:
        return False
    current = ROOT
    for part in relative.parts:
        try:
            names = {child.name for child in current.iterdir()}
        except OSError:
            return False
        if part not in names:
            return False
        current /= part
    return True


def strip_heading_markup(value: str) -> str:
    value = re.sub(r"\s+#+\s*$", "", value)
    value = re.sub(r"<[^>]+>", "", value)
    value = re.sub(r"!\[([^\]]*)\]\([^)]*\)", r"\1", value)
    value = re.sub(r"\[([^\]]+)\]\([^)]*\)", r"\1", value)
    return value.replace("`", "").strip()


def github_slug(value: str) -> str:
    value = strip_heading_markup(value).lower()
    value = re.sub(r"[^\w\- ]", "", value, flags=re.UNICODE)
    return re.sub(r"\s", "-", value)


def anchors(path: Path) -> set[str]:
    seen: Counter[str] = Counter()
    result: set[str] = set()
    in_fence = False
    fence_token = ""
    for raw in path.read_text("utf-8").splitlines():
        fence = FENCE_RE.match(raw)
        if fence:
            token = fence.group(1)
            if not in_fence:
                in_fence = True
                fence_token = token[0]
            elif token[0] == fence_token:
                in_fence = False
            continue
        if in_fence:
            continue
        match = HEADING_RE.match(raw)
        if not match:
            continue
        base = github_slug(match.group(2))
        duplicate = seen[base]
        seen[base] += 1
        result.add(base if duplicate == 0 else f"{base}-{duplicate}")
    return result


def validate_markdown(path: Path, all_anchors: dict[Path, set[str]]) -> tuple[list[str], set[Path]]:
    errors: list[str] = []
    referenced_images: set[Path] = set()
    relative = path.relative_to(ROOT)
    text = path.read_text("utf-8")
    lines = text.splitlines()

    if PERSONAL_PATH_RE.search(text):
        errors.append(f"{relative}: contains a personal absolute path")

    headings: list[tuple[int, int, str]] = []
    in_fence = False
    fence_char = ""
    fence_line = 0
    for number, raw in enumerate(lines, 1):
        fence = FENCE_RE.match(raw)
        if fence:
            token = fence.group(1)
            if not in_fence:
                if not fence.group(2).strip():
                    errors.append(f"{relative}:{number}: opening code fence has no language")
                in_fence = True
                fence_char = token[0]
                fence_line = number
            elif token[0] == fence_char:
                in_fence = False
            continue
        if in_fence:
            continue
        heading = HEADING_RE.match(raw)
        if heading:
            headings.append((number, len(heading.group(1)), heading.group(2)))

    if in_fence:
        errors.append(f"{relative}:{fence_line}: unclosed code fence")
    h1_count = sum(level == 1 for _, level, _ in headings)
    if h1_count != 1:
        errors.append(f"{relative}: expected one H1, found {h1_count}")
    previous = 0
    for number, level, _ in headings:
        if previous and level > previous + 1:
            errors.append(f"{relative}:{number}: heading level jumps from H{previous} to H{level}")
        previous = level

    for match in LINK_RE.finditer(text):
        is_image = bool(match.group(1))
        raw_target = match.group(2)
        target = raw_target[1:-1] if raw_target.startswith("<") and raw_target.endswith(">") else raw_target
        target = unquote(target)
        split = urlsplit(target)
        if split.scheme in {"http", "https", "mailto"} or target.startswith("//"):
            continue
        if split.scheme or split.netloc:
            errors.append(f"{relative}: unsupported link target {raw_target}")
            continue

        target_path = path if not split.path else (path.parent / split.path).resolve()
        try:
            target_path.relative_to(ROOT)
        except ValueError:
            errors.append(f"{relative}: link escapes repository: {raw_target}")
            continue
        if not target_path.exists():
            errors.append(f"{relative}: broken link: {raw_target}")
            continue
        if not has_exact_case(target_path):
            errors.append(f"{relative}: case-mismatched link: {raw_target}")
            continue
        if target_path.is_dir():
            readme = target_path / "README.md"
            if readme.is_file():
                target_path = readme
            else:
                errors.append(f"{relative}: directory link has no README.md: {raw_target}")
                continue
        if split.fragment and target_path.suffix.lower() == ".md":
            fragment = unquote(split.fragment).lower()
            if fragment not in all_anchors.get(target_path, set()):
                errors.append(f"{relative}: broken heading anchor: {raw_target}")
        if is_image:
            if target_path.suffix.lower() not in IMAGE_SUFFIXES:
                errors.append(f"{relative}: image link has unsupported suffix: {raw_target}")
            referenced_images.add(target_path)

    return errors, referenced_images


def validate_assets(images: list[Path], referenced: set[Path]) -> list[str]:
    errors: list[str] = []
    assets_root = ROOT / "docs" / "assets"
    screenshots_root = assets_root / "screenshots"
    for path in images:
        relative = path.relative_to(ROOT)
        if not path.is_relative_to(assets_root):
            errors.append(f"{relative}: documentation image must live under docs/assets/")
        if path.is_relative_to(screenshots_root) and FORBIDDEN_IMAGE_NAME_RE.search(path.name):
            errors.append(f"{relative}: screenshot filename is not release-safe")
        if path not in referenced:
            errors.append(f"{relative}: documentation image is not referenced")
    for path in referenced:
        if path.suffix.lower() in IMAGE_SUFFIXES and path not in images:
            errors.append(f"{path.relative_to(ROOT)}: referenced image was not inventoried")
    return errors


def main() -> int:
    markdown = markdown_files()
    all_anchors = {path.resolve(): anchors(path) for path in markdown}
    errors: list[str] = []
    referenced_images: set[Path] = set()
    for path in markdown:
        file_errors, file_images = validate_markdown(path, all_anchors)
        errors.extend(file_errors)
        referenced_images.update(file_images)
    images = sorted(set(image_files()) | {path for path in referenced_images if path.is_file()})
    errors.extend(validate_assets(images, referenced_images))

    if errors:
        print(f"FAIL: documentation validation found {len(errors)} issue(s)", file=sys.stderr)
        for error in errors:
            print(f"- {error}", file=sys.stderr)
        return 6
    print(
        f"PASS: documentation validation ({len(markdown)} Markdown files, "
        f"{len(images)} referenced image assets)"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
