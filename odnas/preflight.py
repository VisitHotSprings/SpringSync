r"""Preflight filename scan (SPEC §6.1 step 5). Names and sizes only, never contents.
The detailed list is shown only to the user; admins/auditors see counts.

v0.9 (§6.1, §9.8):
- the OneDrive rules (blocked names, 400-char paths, 250 GB files, quota) apply only to OneDrive users;
- Google users: duplicate names in one folder (rclone skips them), Google-native files (size -1 in a
  listing with gdocs on: skipped, or exported with gdocs_mode=export), names containing `/` (rclone shows
  them as the full-width look-alike U+FF0F);
- Windows host rules on BOTH hosts, as warnings (rule names start with `win_`): reserved device names
  (incl. COM¹-COM³ / LPT¹-LPT³, with or without an extension), a name ending in a space or a dot, the
  characters " * : < > ? \ | and control characters, and the UNC path staff see over 259 characters;
- one-way users: provider rules on the cloud side only, plus the count of NAS-only files (Mirror would
  move them to the backup target)."""
from __future__ import annotations

import re
from collections import Counter, defaultdict
from dataclasses import dataclass, field

BLOCKED_EXACT = {".lock", "con", "prn", "aux", "nul", "desktop.ini"} | \
    {f"com{i}" for i in range(10)} | {f"lpt{i}" for i in range(10)}
MAX_PATH = 400                       # full path must be under 400 characters
MAX_FILE = 250 * 1024 ** 3           # 250 GB
MAX_FOLDER_ITEMS = 100_000
WIN_RESERVED = {"con", "prn", "aux", "nul"} | {f"com{i}" for i in "123456789\u00b9\u00b2\u00b3"} | \
    {f"lpt{i}" for i in "123456789\u00b9\u00b2\u00b3"}
WIN_BAD_CHARS = re.compile(r'["*:<>?\\|\x01-\x1f]')
WIN_MAX_UNC = 259
WARNING_PREFIX = "win_"


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

    nas_only: int | None = None      # one-way users: NAS files with no cloud counterpart
    gdocs: int | None = None         # Google users: Google-native files

    def summary(self) -> str:
        c = self.counts()
        s = ", ".join(f"{k}: {v}" for k, v in sorted(c.items())) or "no problems found"
        if self.gdocs is not None:
            s += f"; Google-native files: {self.gdocs}"
        if self.nas_only is not None:
            s += f"; NAS-only files: {self.nas_only}"
        return s


def windows_findings(path: str, side: str, unc_prefix: str | None) -> list[Finding]:
    """SPEC v0.9 §9.8 Windows rules (warnings)."""
    out = []
    segs = path.split("/")
    if any(s.split(".", 1)[0].lower() in WIN_RESERVED for s in segs):
        out.append(Finding("win_reserved_name", path, side))
    if any(s.endswith((" ", ".")) for s in segs if s):
        out.append(Finding("win_trailing_space_or_dot", path, side))
    if WIN_BAD_CHARS.search(path):
        out.append(Finding("win_reserved_char", path, side))
    if unc_prefix is not None and len(unc_prefix) + len(path) > WIN_MAX_UNC:
        out.append(Finding("win_path_too_long", path, side))
    return out


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
         block_hash_percent: bool = False, od_prefix_len: int = 0, provider: str = "onedrive",
         one_way: bool = False, unc_prefix: str | None = None, ignore: tuple[str, ...] = ()) -> Report:
    """listings: side -> rclone lsjson entries ({"Path": ..., "Size": ...}). Sides: "onedrive" or
    "google_drive", and "nas".

    od_prefix_len: length of the OneDrive path prefix the files will live under
    (counts toward the 400-character limit). unc_prefix: `\\\\<nas>\\<share>\\` as staff see it.
    ignore: top-level names that are not user data (the check file, the archive folder)."""
    rep = Report()
    all_paths: set[str] = set()
    onedrive = provider == "onedrive"
    cloud_side = "onedrive" if onedrive else "google_drive"
    listings = {side: [e for e in entries if e["Path"].split("/", 1)[0] not in ignore]
                for side, entries in listings.items()}
    if not onedrive and cloud_side in listings:
        entries = listings[cloud_side]
        rep.gdocs = sum(1 for e in entries if int(e.get("Size", 0) or 0) < 0)
        seen = Counter(e["Path"] for e in entries)
        for pth, n in sorted(seen.items()):
            if n > 1:
                rep.findings.append(Finding("google_duplicate_name", pth, cloud_side))
        for pth in sorted(seen):
            if "\uff0f" in pth:
                rep.findings.append(Finding("google_slash_in_name", pth, cloud_side))
    if one_way and cloud_side in listings and "nas" in listings:
        cloud_paths = {e["Path"] for e in listings[cloud_side]}
        rep.nas_only = sum(1 for e in listings["nas"] if e["Path"] not in cloud_paths)
    for side, entries in listings.items():
        for e in entries:
            rep.findings.extend(windows_findings(e["Path"], side, unc_prefix))
        if one_way and side == "nas":
            # only cloud names are transferred; the NAS side gets the Windows warnings above
            rep.total_bytes[side] = sum(max(int(e.get("Size", 0) or 0), 0) for e in entries)
            continue
        if not onedrive:
            # generic rules only (case collisions matter most for Google: case-sensitive -> SMB)
            _generic(rep, side, entries, all_paths)
            continue
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
    if quota_remaining is not None and onedrive and not one_way:
        nas = rep.total_bytes.get("nas", 0)
        rep.quota_exceeded = nas > quota_remaining
        if rep.quota_exceeded:
            rep.findings.append(Finding("onedrive_quota", "(total)", "nas"))
    return rep


def _generic(rep: Report, side: str, entries: list[dict], all_paths: set[str]) -> None:
    lower: defaultdict[str, list[str]] = defaultdict(list)
    per_dir: Counter[str] = Counter()
    total = 0
    for e in entries:
        path = e["Path"]
        total += max(int(e.get("Size", 0) or 0), 0)
        all_paths.add(path)
        per_dir[path.rsplit("/", 1)[0] if "/" in path else ""] += 1
        lower[path.lower()].append(path)
    for variants in lower.values():
        if len(set(variants)) > 1:
            for v in sorted(set(variants)):
                rep.findings.append(Finding("case_collision", v, side))
    for d, n in per_dir.items():
        if n > MAX_FOLDER_ITEMS:
            rep.findings.append(Finding("folder_over_100k_items", d or "/", side))
    rep.total_bytes[side] = total
