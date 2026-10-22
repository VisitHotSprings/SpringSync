#!/usr/bin/env python3
"""Tiny Markdown -> HTML for docs/INSTALL-WINDOWS.md (headings, paragraphs, nested lists, code fences,
tables, block quotes, **bold**, `code`, [links](url)). Then: soffice --headless --convert-to pdf.
Used because pandoc / python-markdown are not on the build box. Not a general Markdown implementation."""
import html
import re
import sys

CSS = """body{font-family:'DejaVu Sans',Arial,sans-serif;font-size:10.5pt;line-height:1.4;margin:1.6cm}
h1{font-size:18pt}h2{font-size:14pt;border-bottom:1px solid #999;margin-top:1.4em}
pre{background:#f2f2f2;border:1px solid #ccc;padding:4px;font-size:8pt}
code{font-family:'DejaVu Sans Mono',monospace;font-size:9pt}table{border-collapse:collapse;font-size:9pt}
td,th{border:1px solid #999;padding:3px 5px;vertical-align:top}blockquote{border-left:4px solid #c60;
margin:0;padding:4px 10px;background:#fff6ee}"""


def inline(s: str) -> str:
    parts = re.split(r"(`[^`]+`)", s)
    out = []
    for p in parts:
        if p.startswith("`") and p.endswith("`") and len(p) > 1:
            out.append("<code>" + html.escape(p[1:-1]) + "</code>")
        else:
            p = html.escape(p, quote=False)
            p = re.sub(r"\*\*([^*]+)\*\*", r"<b>\1</b>", p)
            p = re.sub(r"\[([^\]]+)\]\(([^)]+)\)", r'<a href="\2">\1</a>', p)
            out.append(p)
    return "".join(out)


def convert(md: str) -> str:
    lines = md.split("\n")
    out, i, n = [], 0, len(lines)
    stack = []   # (indent, tag)

    def close_lists(indent=-1):
        while stack and stack[-1][0] > indent:
            out.append(f"</li></{stack.pop()[1]}>")

    while i < n:
        ln = lines[i]
        m = re.match(r"^(\s*)```", ln)
        if m:
            ind = len(m.group(1))
            j = i + 1
            buf = []
            while j < n and not lines[j].strip().startswith("```"):
                buf.append(lines[j][ind:] if lines[j][:ind].strip() == "" else lines[j])
                j += 1
            out.append("<pre>" + html.escape("\n".join(buf)) + "</pre>")
            i = j + 1
            continue
        if not ln.strip():
            i += 1
            continue
        lm = re.match(r"^(\s*)(\d+\.|[-*])\s+(.*)$", ln)
        if lm:
            ind, tag = len(lm.group(1)), ("ol" if lm.group(2)[0].isdigit() else "ul")
            close_lists(ind)
            if stack and stack[-1][0] == ind and stack[-1][1] == tag:
                out.append("</li><li>")
            else:
                if stack and stack[-1][0] == ind:
                    out.append(f"</li></{stack.pop()[1]}>")
                out.append(f"<{tag}><li>")
                stack.append((ind, tag))
            text = [lm.group(3)]
            i += 1
            while i < n and lines[i].strip() and not re.match(r"^\s*(\d+\.|[-*])\s+", lines[i]) \
                    and not lines[i].strip().startswith("```") and len(lines[i]) - len(lines[i].lstrip()) > ind:
                text.append(lines[i].strip())
                i += 1
            out.append(inline(" ".join(text)))
            continue
        if stack and (len(ln) - len(ln.lstrip())) == 0:
            close_lists()
        if ln.startswith("#"):
            h = len(ln) - len(ln.lstrip("#"))
            out.append(f"<h{h}>{inline(ln[h:].strip())}</h{h}>")
            i += 1
            continue
        if ln.strip() == "---":
            out.append("<hr>")
            i += 1
            continue
        if ln.startswith("|"):
            rows = []
            while i < n and lines[i].startswith("|"):
                rows.append([c.strip() for c in lines[i].strip().strip("|").split("|")])
                i += 1
            out.append("<table>")
            for k, r in enumerate(rows):
                if k == 1 and all(re.fullmatch(r":?-+:?", c) for c in r):
                    continue
                t = "th" if k == 0 else "td"
                out.append("<tr>" + "".join(f"<{t}>{inline(c)}</{t}>" for c in r) + "</tr>")
            out.append("</table>")
            continue
        if ln.startswith(">"):
            buf = []
            while i < n and lines[i].startswith(">"):
                buf.append(lines[i][1:].strip())
                i += 1
            paras = "\n".join(buf).split("\n\n")
            out.append("<blockquote>" + "".join(f"<p>{inline(' '.join(p.split()))}</p>" for p in paras) + "</blockquote>")
            continue
        buf = []
        while i < n and lines[i].strip() and not re.match(r"^(#|\||>|\s*```|\s*(\d+\.|[-*])\s)", lines[i]):
            buf.append(lines[i].strip())
            i += 1
        if buf:
            out.append("<p>" + inline(" ".join(buf)) + "</p>")
        else:
            i += 1
    close_lists()
    return ("<!DOCTYPE html><html><head><meta charset='utf-8'><title>SpringSync on Windows</title>"
            f"<style>{CSS}</style></head><body>" + "\n".join(out) + "</body></html>")


if __name__ == "__main__":
    src, dst = sys.argv[1], sys.argv[2]
    open(dst, "w", encoding="utf-8").write(convert(open(src, encoding="utf-8").read()))
