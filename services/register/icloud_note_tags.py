# -*- coding: utf-8 -*-
"""HME note platform tags: comma-separated multi-platform markers."""
from __future__ import annotations
from typing import Iterable, List

DEFAULT_PLATFORM = "chatgpt"


def parse_note_tags(note: str | None) -> List[str]:
    text = str(note or "").strip()
    if not text:
        return []
    for sep in (";", "|", "/", "\uff0c"):
        text = text.replace(sep, ",")
    raw = []
    for part in text.split(","):
        tag = part.strip().lower()
        if tag:
            raw.append(tag)
    out, seen = [], set()
    for tag in raw:
        if tag not in seen:
            seen.add(tag)
            out.append(tag)
    return out


def format_note_tags(tags: Iterable[str]) -> str:
    out, seen = [], set()
    for tag in tags:
        t = str(tag or "").strip().lower()
        if t and t not in seen:
            seen.add(t)
            out.append(t)
    return ",".join(out)


def note_has_platform(note: str | None, platform: str = DEFAULT_PLATFORM) -> bool:
    p = str(platform or DEFAULT_PLATFORM).strip().lower() or DEFAULT_PLATFORM
    return p in parse_note_tags(note)


def note_add_platform(note: str | None, platform: str = DEFAULT_PLATFORM) -> str:
    p = str(platform or DEFAULT_PLATFORM).strip().lower() or DEFAULT_PLATFORM
    tags = parse_note_tags(note)
    if p not in tags:
        tags.append(p)
    return format_note_tags(tags)


def note_remove_platform(note: str | None, platform: str = DEFAULT_PLATFORM) -> str:
    p = str(platform or DEFAULT_PLATFORM).strip().lower() or DEFAULT_PLATFORM
    tags = [t for t in parse_note_tags(note) if t != p]
    return format_note_tags(tags)
