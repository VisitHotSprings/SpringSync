#!/usr/bin/env python3
"""Static checks for the Windows PowerShell scripts, runnable on Linux (no pwsh / PSScriptAnalyzer here).

NOT a PowerShell parser. It catches what breaks scripts most often or what Mark asked to avoid:
  * brackets ( ) { } [ ] balanced outside strings and comments (here-strings, $( ) in "..." handled)
  * ASCII only (Windows PowerShell 5.1 reads BOM-less files as ANSI)
  * none of: Invoke-Expression / iex, -EncodedCommand, DownloadString/DownloadFile, Invoke-WebRequest or
    Invoke-RestMethod to anything but 127.0.0.1, Start-BitsTransfer, Set-/Add-MpPreference (Defender),
    -WindowStyle Hidden, Set-ExecutionPolicy, Remove-Item on the "current" junction (would follow it)
  * every script starts with comment-based help and has [CmdletBinding(SupportsShouldProcess)]
Usage: ps_static_check.py FILE...   (exit 1 on any finding)
"""
import re
import sys
from pathlib import Path

FORBIDDEN = [
    (re.compile(r"\bInvoke-Expression\b|(^|[\s;|(])iex(\s|$)", re.I | re.M), "Invoke-Expression"),
    (re.compile(r"-Enc(odedCommand)?\b", re.I), "-EncodedCommand"),
    (re.compile(r"Download(String|File|Data)", re.I), "WebClient download"),
    (re.compile(r"Start-BitsTransfer", re.I), "BITS download"),
    (re.compile(r"(Set|Add|Remove)-MpPreference", re.I), "Defender settings"),
    (re.compile(r"-WindowStyle\s+Hidden", re.I), "hidden window"),
    (re.compile(r"Set-ExecutionPolicy", re.I), "changes execution policy"),
    (re.compile(r"FromBase64String", re.I), "base64 payload"),
]
WEB = re.compile(r"Invoke-(WebRequest|RestMethod)\b[^\n]*", re.I)


class ParseError(Exception):
    pass


def strip_code(src: str) -> str:
    """Return the code with strings and comments blanked (newlines kept), checking brackets on the way."""
    out, stack, i, n, line = [], [], 0, len(src), 1
    pairs = {")": "(", "}": "{", "]": "["}

    def err(msg):
        raise ParseError(f"line {line}: {msg}")

    def dq_string(i, close='"'):
        """i at first char after the opening quote. Handles `-escapes and $( ) subexpressions."""
        nonlocal line
        while i < n:
            c = src[i]
            if c == "\n":
                line += 1
            if c == "`":
                i += 2
                continue
            if c == '"' and close == '"':
                if i + 1 < n and src[i + 1] == '"':
                    i += 2
                    continue
                return i + 1
            if close == '"@' and src.startswith('\n"@', i):
                line += 1
                return i + 3
            if c == "$" and i + 1 < n and src[i + 1] == "(":
                i = code(i + 2, ")")
                continue
            i += 1
        err("unterminated double-quoted string")

    def code(i, until=None):
        nonlocal line
        depth0 = len(stack)
        while i < n:
            c = src[i]
            if c == "\n":
                line += 1
                out.append("\n")
                i += 1
                continue
            if src.startswith("<#", i):
                j = src.find("#>", i + 2)
                if j < 0:
                    err("unterminated block comment")
                line += src.count("\n", i, j)
                out.append("\n" * src.count("\n", i, j))
                i = j + 2
                continue
            if c == "#":
                j = src.find("\n", i)
                i = n if j < 0 else j
                continue
            if c == "`":
                i += 2
                continue
            if src.startswith("@'", i) and src[i + 2:i + 3] in ("\n", "\r"):
                j = src.find("\n'@", i)
                if j < 0:
                    err("unterminated here-string")
                line += src.count("\n", i, j + 1)
                i = j + 3
                continue
            if src.startswith('@"', i) and src[i + 2:i + 3] in ("\n", "\r"):
                i = dq_string(i + 2, '"@')
                continue
            if c == "'":
                j = i + 1
                while True:
                    k = src.find("'", j)
                    if k < 0:
                        err("unterminated single-quoted string")
                    if src[k + 1:k + 2] == "'":
                        j = k + 2
                        continue
                    break
                line += src.count("\n", i, k)
                i = k + 1
                out.append("''")
                continue
            if c == '"':
                i = dq_string(i + 1)
                out.append('""')
                continue
            if c in "({[":
                stack.append((c, line))
            elif c in ")}]":
                if until == ")" and c == ")" and len(stack) == depth0:
                    return i + 1
                if not stack or stack[-1][0] != pairs[c]:
                    err(f"unbalanced '{c}'")
                stack.pop()
            out.append(c)
            i += 1
        if until:
            err("unterminated $( )")
        return i

    code(0)
    if stack:
        raise ParseError(f"unclosed '{stack[-1][0]}' opened on line {stack[-1][1]}")
    return "".join(out)


def check(path: Path) -> list[str]:
    raw = path.read_bytes()
    found = []
    try:
        raw.decode("ascii")
    except UnicodeDecodeError as e:
        found.append(f"non-ASCII byte at offset {e.start}")
    src = raw.decode("utf-8", "replace").replace("\r\n", "\n")
    try:
        codeonly = strip_code(src)
    except ParseError as e:
        return found + [f"parse: {e}"]
    for rx, what in FORBIDDEN:
        if rx.search(codeonly):
            found.append(f"forbidden: {what}")
    for m in WEB.finditer(src):
        if "127.0.0.1" not in m.group(0):
            found.append(f"web call not to loopback: {m.group(0)[:80]}")
    if re.search(r"Remove-Item[^\n]*\$P\.Current\b", src):
        found.append("Remove-Item on the current junction (use [IO.Directory]::Delete(path, $false))")
    if path.suffix == ".ps1":
        if not src.lstrip().startswith("<#"):
            found.append("no comment-based help at the top")
        if "[CmdletBinding(SupportsShouldProcess)]" not in src:
            found.append("no [CmdletBinding(SupportsShouldProcess)] (-WhatIf)")
    return found


def main(argv):
    bad = 0
    for f in argv:
        probs = check(Path(f))
        for p in probs:
            print(f"{f}: {p}")
        bad += bool(probs)
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
