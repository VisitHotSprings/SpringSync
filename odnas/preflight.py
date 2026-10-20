"""Preflight filename scan (SPEC §6.1 step 5). Names and sizes only, never contents.
The detailed list is shown only to the user; admins/auditors see counts."""
from __future__ import annotations

import re
from collections import Counter, defaultdict
from dataclasses import dataclass, field

BLOCKED_EXACT = {".lock", "con", "prn", "aux", "nul", "desktop.ini"} | \
    {f"com{i}" for i in range(10)} | {f"lpt{i}" for i in range(10)}
MAX_PATH = 400                       # full path must be under 400 characters
MAX_FILE = 250 * 1024 ** 3           # 250 GB
MAX_FOLDER_ITEMS = 100_000


@dataclass
class Finding:
    rule: str
    path: str
    side: str


@dataclass
class Report:
    findings: list[Finding] = field(default_factory=list)
    total_bytes: dict[str, int] = field(default_factory=dict)
    quota_exceeded: bool = False

    def counts(self) -> dict[str, int]:
        return dict(Counter(f.rule for f in self.findings))

    def summary(self) -> str:
        c = self.counts()
        return ", ".join(f"{k}: {v}" for k, v in sorted(c.items())) or "no problems found"


def blocked_name(name: str, block_hash_percent: bool = False) -> bool:
    n = name.lower()
    stem = n.split(".", 1)[0]
    if n in BLOCKED_EXACT or stem in BLOCKED_EXACT - {".lock", "desktop.ini"}:
        return True
    if n.startswith("~$") or "_vti_" in n:
        return True
    if block_hash_percent and ("#" in name or "%" in name):
        return True
    return False


def scan(listings: dict[str, list[dict]], *, quota_remaining: int | None = None,
         block_hash_percent: bool = False, od_prefix_len: int = 0) -> Report:
    """listings: side -> rclone lsjson entries ({"Path": ..., "Size": ...}).

    od_prefix_len: length of the OneDrive path prefix the files will live under
    (counts toward the 400-character limit)."""
    rep = Report()
    all_paths: set[str] = set()
    for side, entries in listings.items():
        lower: defaultdict[str, list[str]] = defaultdict(list)
        per_dir: Counter[str] = Counter()
        total = 0
        for e in entries:
            path = e["Path"]
            size = int(e.get("Size", 0) or 0)
            total += max(size, 0)
            all_paths.add(path)
            name = path.rsplit("/", 1)[-1]
            parent = path.rsplit("/", 1)[0] if "/" in path else ""
            per_dir[parent] += 1
            for seg in path.split("/"):
                if blocked_name(seg, block_hash_percent):
                    rep.findings.append(Finding("blocked_name", path, side))
                    break
            if len(path) + od_prefix_len >= MAX_PATH:
                rep.findings.append(Finding("path_too_long", path, side))
            if size >= MAX_FILE:
                rep.findings.append(Finding("file_too_large", path, side))
            lower[path.lower()].append(path)
            if re.search(r"(^|/)\s|\s($|/)|\.($|/)", path):
                rep.findings.append(Finding("leading_trailing_space_or_dot", path, side))
            del name
        for variants in lower.values():
            if len(set(variants)) > 1:
                for v in sorted(set(variants)):
                    rep.findings.append(Finding("case_collision", v, side))
        for d, n in per_dir.items():
            if n > MAX_FOLDER_ITEMS:
                rep.findings.append(Finding("folder_over_100k_items", d or "/", side))
        rep.total_bytes[side] = total
    if quota_remaining is not None:
        nas = rep.total_bytes.get("nas", 0)
        rep.quota_exceeded = nas > quota_remaining
        if rep.quota_exceeded:
            rep.findings.append(Finding("onedrive_quota", "(total)", "nas"))
    return rep
