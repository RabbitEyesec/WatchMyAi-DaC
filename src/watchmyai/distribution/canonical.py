"""RFC 8785 canonicalization for the integer-only WatchMyAI I-JSON profile.

Signed WatchMyAI metadata has no floating-point fields. Rejecting floats makes
the accepted profile unambiguous while the resulting representation is RFC
8785 JCS for every accepted value.
"""

from __future__ import annotations

import json
import math
from typing import Any

MAX_SAFE_INTEGER = (2**53) - 1


class CanonicalJSONError(ValueError):
    pass


def _integer(raw: str) -> int:
    value = int(raw)
    if not -MAX_SAFE_INTEGER <= value <= MAX_SAFE_INTEGER:
        raise CanonicalJSONError("integer exceeds the interoperable I-JSON range")
    return value


def _float(_: str) -> float:
    raise CanonicalJSONError("floating-point values are outside the WatchMyAI signed profile")


def _constant(_: str) -> Any:
    raise CanonicalJSONError("non-finite JSON numbers are prohibited")


def _object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise CanonicalJSONError(f"duplicate object member {key!r}")
        result[key] = value
    return result


def load_strict_json(raw: bytes | str) -> Any:
    if isinstance(raw, bytes):
        try:
            text = raw.decode("utf-8", "strict")
        except UnicodeDecodeError as exc:
            raise CanonicalJSONError("metadata is not valid UTF-8") from exc
    else:
        text = raw
    try:
        value = json.loads(
            text,
            object_pairs_hook=_object,
            parse_int=_integer,
            parse_float=_float,
            parse_constant=_constant,
        )
    except json.JSONDecodeError as exc:
        raise CanonicalJSONError(f"invalid JSON: {exc.msg}") from exc
    _validate(value)
    return value


def _validate(value: Any) -> None:
    if value is None or isinstance(value, (bool, str)):
        if isinstance(value, str) and any(0xD800 <= ord(char) <= 0xDFFF for char in value):
            raise CanonicalJSONError("unpaired Unicode surrogate is prohibited")
        return
    if isinstance(value, int) and not isinstance(value, bool):
        if not -MAX_SAFE_INTEGER <= value <= MAX_SAFE_INTEGER:
            raise CanonicalJSONError("integer exceeds the interoperable I-JSON range")
        return
    if isinstance(value, float):
        if not math.isfinite(value):
            raise CanonicalJSONError("non-finite number is prohibited")
        raise CanonicalJSONError("floating-point values are outside the WatchMyAI signed profile")
    if isinstance(value, list):
        for item in value:
            _validate(item)
        return
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                raise CanonicalJSONError("object keys must be strings")
            _validate(key)
            _validate(item)
        return
    raise CanonicalJSONError(f"unsupported JSON value {type(value).__name__}")


def canonicalize(value: Any) -> bytes:
    _validate(value)
    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
