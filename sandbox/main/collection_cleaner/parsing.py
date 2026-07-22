"""Parsing and numeric serialization helpers."""

from __future__ import annotations

import math
import re
from typing import Any

from .constants import SUCCESS_FALSE, SUCCESS_TRUE, UNIT_FACTORS


SIZE_TOKEN_RE = re.compile(r"^([+-]?(?:\d+(?:\.\d*)?|\.\d+))\s*([A-Za-z]*)$")
SI_UNIT_ALIASES = {
    "kb": "KB",
    "mb": "MB",
    "gb": "GB",
    "tb": "TB",
}


def parse_float(value: str | None) -> float | None:
    if value is None:
        return None
    text = value.strip()
    if not text:
        return None
    try:
        return float(text)
    except ValueError:
        return None


def parse_int(value: str | None) -> int | None:
    fval = parse_float(value)
    if fval is None:
        return None
    return int(fval)


def parse_success(value: str | None) -> float | None:
    if value is None:
        return None
    text = value.strip().lower()
    if text in SUCCESS_TRUE:
        return 1.0
    if text in SUCCESS_FALSE:
        return 0.0
    return None


def parse_percent(value: str | None) -> float | None:
    if value is None:
        return None
    text = value.strip()
    if not text:
        return None
    if text.endswith("%"):
        text = text[:-1]
    return parse_float(text)


def parse_size_scalar(token: str) -> float | None:
    token = token.strip()
    if not token:
        return None

    match = SIZE_TOKEN_RE.match(token)
    if not match:
        return None

    num = float(match.group(1))
    unit = match.group(2).strip()
    unit_key = SI_UNIT_ALIASES.get(unit.lower(), unit.upper())

    factor = UNIT_FACTORS.get(unit_key)
    if factor is None:
        return None
    return num * factor


def parse_pair_to_bytes(value: str | None) -> tuple[float | None, float | None]:
    if value is None:
        return (None, None)

    parts = value.split("/")
    if len(parts) != 2:
        return (None, None)

    left = parse_size_scalar(parts[0])
    right = parse_size_scalar(parts[1])
    return (left, right)


def parse_boolish_field(value: str) -> bool:
    text = value.strip().lower()
    return text not in {"", "0", "false", "f", "no", "n"}


def is_numeric_value(value: Any) -> bool:
    if value is None:
        return True
    if isinstance(value, bool):
        return False
    return isinstance(value, (int, float))


def numeric_to_csv(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, float) and math.isnan(value):
        return ""
    if isinstance(value, bool):
        return ""
    if isinstance(value, int):
        return str(value)
    if isinstance(value, float):
        # Deterministic compact float representation.
        return f"{value:.12g}"
    return ""
