from watchmyai.classifiers.command import classify_command
from watchmyai.classifiers.path import classify_paths, resolve_paths
from watchmyai.classifiers.resource import destination_approved, repository_approved

__all__ = [
    "classify_command",
    "classify_paths",
    "destination_approved",
    "repository_approved",
    "resolve_paths",
]
