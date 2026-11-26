#!/usr/bin/env python3
"""Deterministic build-time search index generator for the Mirage docs site.

Reads the markdown pages under docs/ plus docs/_data/nav.yml and writes
docs/search.json — a single static file the client-side search dialog
(docs/assets/js/search.js) fetches on first open. No server, no third-party
engine, no build hook: run this tool and commit the output, exactly like
tools/sync_site_docs.py commits its mirrors and manifests.

What is indexed
  Every navigation page that is a markdown file (31 pages: nav.yml minus the
  llms.txt and docs.json machine manifests). Skipped by policy:
    - docs/404.md — a dead end, never worth a search hit;
    - docs/index.md — the landing page is hand-rolled HTML with no markdown
      headings, and navigation (which defines a page's "section") does not
      list it;
    - markdown without front matter (docs/data/token-formats.md and the
      verbatim data mirrors) — data files, not pages.
  Mirrored pages (front matter carries a `source:` key — spec/, README,
  CHANGELOG) are indexed like any other page; the mirror banner is a
  provenance note, not a content difference.

Page order
  nav.yml section order first (guide, reference, spec, deploy, project,
  agent), then each page's `order` front-matter key — the same order the
  sidebar and the pager render. Consumers can treat a lower position in
  `pages` as "listed earlier in the manual".

Sections and anchor ids
  Each body is split at ## and ### headings (outside fenced code blocks).
  Text before the first heading becomes an implicit intro section with the
  empty id and empty heading; the client links such a result to the page
  itself. Every other section carries the heading text and its anchor id.

  The id is a byte-exact replication of what the deployed site renders.
  Jekyll builds with kramdown input GFM, where kramdown-parser-gfm's
  generate_gfm_header_id (not kramdown's own generator, and not the
  site.js TOC fallback, which only runs when a heading has no id) assigns
  every heading an id:
      lowercase -> delete everything but [word chars, -, space, tab]
      -> each space/tab becomes "-" -> repeats on the same page get
      "-1", "-2", ... appended (counter runs across all heading levels)
  Inline markup is dropped first the way kramdown's update_raw_text does
  it (code spans keep their text, emphasis markers vanish, links keep
  their label). The result matches the ids the right-rail TOC links to,
  so #section anchors from search land on the right heading. tools/ has a
  validation harness that proves this against the live site's ids.

Code blocks
  Excluded from section text. Every identifier a reader searches for —
  config keys, CLI verbs, header names, event fields — is documented in
  prose or tables on the same page (e.g. `connectors.webhook.url` is in the
  configuration table), so search loses nothing while snippets stay
  readable prose instead of half a YAML blob.

Determinism
  Sorted iteration, no timestamps, no environment, no randomness: the
  "generated" field is the literal string "tools/build_search.py". Two
  runs over the same tree are byte-identical (verify with sha256sum).
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

import yaml

REPO = Path(__file__).resolve().parent.parent
DOCS = REPO / "docs"
NAV_PATH = DOCS / "_data" / "nav.yml"
OUT_PATH = DOCS / "search.json"

GENERATED = "tools/build_search.py"

FRONT_MATTER_RE = re.compile(r"\A---\n(.*?)\n---\n", re.DOTALL)
FENCE_RE = re.compile(r"^ {0,3}(`{3,}|~{3,})")
HEADING_RE = re.compile(r"^ {0,3}(#{1,6})[ \t]+(.*?)(?:[ \t]+#+)?[ \t]*$")
# Inline markup stripped the way kramdown's update_raw_text reduces a
# heading/link to its text (kept in one place so headings and body text
# normalize identically).
CODE_SPAN_RE = re.compile(r"`+([^`]*)`+")
EMPHASIS_RE = re.compile(r"(\*\*|__)(.*?)\1|\*(.*?)\*")
LINK_RE = re.compile(r"!?\[([^\]]*)\]\([^)]*\)")
REF_LINK_RE = re.compile(r"\[([^\]]*)\](?:\[[^\]]*\])?")
LINK_DEF_RE = re.compile(r"^\s*\[[^\]]+\]:\s")
HTML_TAG_RE = re.compile(r"</?[A-Za-z][^>]*>")
ENTITY_RE = re.compile(r"&(amp|lt|gt|quot|apos|#39|#x27);")
RAW_TAG_RE = re.compile(r"\{%\s*(?:raw|endraw)\s*%\}")
TABLE_ROW_RE = re.compile(r"^\s*\|(.+)\|\s*$")
TABLE_SEP_RE = re.compile(r"^[\s|:-]+$")
LIST_MARKER_RE = re.compile(r"^\s*(?:[-*+]|\d+\.)\s+")
BLOCKQUOTE_RE = re.compile(r"^\s*>\s?")
HR_RE = re.compile(r"^ {0,3}(?:(?:-[ \t]*){3,}|(?:\*[ \t]*){3,}|(?:_[ \t]*){3,})$")
# kramdown-parser-gfm NON_WORD_RE = /[^\p{Word}\- \t]/ — Python's \w is
# the ASCII-compatible equivalent of \p{Word} for this corpus.
NON_WORD_RE = re.compile(r"[^\w\- \t]")


def read_front_matter(path: Path) -> tuple[dict, str]:
    """Split a markdown file into (front matter dict, body)."""
    text = path.read_text(encoding="utf-8")
    m = FRONT_MATTER_RE.match(text)
    if not m:
        return {}, text
    try:
        data = yaml.safe_load(m.group(1))
    except yaml.YAMLError as e:
        sys.exit(f"build_search: {path}: front matter is not valid YAML ({e})")
    body = text[m.end():]
    return (data if isinstance(data, dict) else {}), body


def strip_inline(text: str) -> str:
    """Reduce inline markdown to the text kramdown would render (and feed
    to update_raw_text): code spans keep their content, emphasis markers
    and link/image targets vanish, labels stay, raw-tag fences unwrap."""
    text = RAW_TAG_RE.sub("", text)
    text = LINK_RE.sub(r"\1", text)
    text = REF_LINK_RE.sub(r"\1", text)
    text = CODE_SPAN_RE.sub(r"\1", text)
    text = EMPHASIS_RE.sub(lambda m: m.group(2) or m.group(3) or "", text)
    text = HTML_TAG_RE.sub("", text)
    text = ENTITY_RE.sub(
        lambda m: {"&amp;": "&", "&lt;": "<", "&gt;": ">", "&quot;": '"',
                   "&apos;": "'", "&#39;": "'", "&#x27;": "'"}.get(m.group(0), m.group(0)),
        text,
    )
    return text


def gfm_anchor(text: str) -> str:
    """Replicate kramdown-parser-gfm's generate_gfm_header_id:
    downcase, delete non-[\\w- \\t], space/tab -> "-", no dedup suffix
    (the caller appends "-N" on repeats, like the parser's id counter)."""
    result = text.lower()
    result = NON_WORD_RE.sub("", result)
    return result.replace(" ", "-").replace("\t", "-")


def plain_text_line(line: str) -> str:
    """One body line -> plain searchable prose (tables flatten to their
    cells, list/quote markers drop, markup strips; empty result = skip)."""
    if FENCE_RE.match(line) or HR_RE.match(line) or LINK_DEF_RE.match(line):
        return ""
    line = strip_inline(line)
    if TABLE_ROW_RE.match(line):
        if TABLE_SEP_RE.match(line):
            return ""
        line = TABLE_ROW_RE.match(line).group(1)  # type: ignore[union-attr]
        line = " ".join(cell.strip() for cell in line.split("|"))
    line = BLOCKQUOTE_RE.sub("", line)
    line = LIST_MARKER_RE.sub("", line)
    # Backticks that survive here belong to code spans opened on another
    # line (markdown allows them to span lines); in plain text they are
    # markup noise, never prose characters.
    line = line.replace("`", "")
    return re.sub(r"\s+", " ", line).strip()


def balanced(line: str) -> bool:
    """True when a line carries no markup opened but not closed on it —
    markdown allows code spans, emphasis and link labels to wrap to the
    next line, and those constructs must be stripped as a whole."""
    return (
        line.count("`") % 2 == 0
        and line.count("[") == line.count("]")
        and line.count("**") % 2 == 0
        and line.count("__") % 2 == 0
    )


def logical_lines(lines: list[str]) -> list[str]:
    """Merge wrapped lines: an unbalanced line grows until the construct
    closes (or the paragraph ends), so multi-line links, code spans and
    emphasis survive inline stripping intact."""
    out: list[str] = []
    buf = ""
    for line in lines:
        buf = f"{buf} {line}" if buf else line
        if balanced(buf):
            out.append(buf)
            buf = ""
    if buf.strip():
        out.append(buf)
    return out


def parse_page(body: str) -> list[dict]:
    """Split a markdown body into sections: the intro before the first
    heading (id "" if non-empty), then one section per ## / ### heading
    with its live anchor id. Fenced code blocks are skipped entirely
    (they are excluded from the index, and a # inside them is not a
    heading). The dedup counter runs over every heading level, mirroring
    the parser's single per-document id counter."""
    sections: list[dict] = []
    counts: dict[str, int] = {}
    current: dict | None = None
    fence = ""
    para: list[str] = []

    def flush() -> None:
        nonlocal current, para
        for logical in logical_lines(para):
            text = plain_text_line(logical)
            if not text:
                continue
            if current is None:
                current = {"id": "", "heading": "", "text": ""}
                sections.append(current)
            current["text"] += (" " if current["text"] else "") + text
        para = []

    for line in body.split("\n"):
        if fence:
            if re.match(r"^ {0,3}" + re.escape(fence[0]) + "{3,}[ \t]*$", line):
                fence = ""
            continue
        if FENCE_RE.match(line):
            fence = FENCE_RE.match(line).group(1)  # type: ignore[union-attr]
            flush()
            continue
        m = HEADING_RE.match(line)
        if m:
            flush()
            level = len(m.group(1))
            text = re.sub(r"\s+", " ", strip_inline(m.group(2)).strip())
            anchor = gfm_anchor(text)
            counts[anchor] = counts.get(anchor, 0) + 1
            if counts[anchor] > 1:
                anchor = f"{anchor}-{counts[anchor] - 1}"
            if level in (2, 3):
                current = {"id": anchor, "heading": text, "text": ""}
                sections.append(current)
            else:
                # h1/h4-h6 keep the counter alive but do not split a
                # section; their (rare) text stays in the open section.
                if current is not None:
                    current["text"] += (" " if current["text"] else "") + text
            continue
        if not line.strip() or HR_RE.match(line) or LINK_DEF_RE.match(line):
            flush()
            continue
        para.append(line)
    flush()

    return sections


def nav_pages() -> list[tuple[str, str, str, int]]:
    """(url, docs-relative path, section title, position in the flattened
    nav) for every nav item that points at a markdown page."""
    data = yaml.safe_load(NAV_PATH.read_text(encoding="utf-8"))
    out: list[tuple[str, str, str, int]] = []
    position = 0
    for section in data.get("sections", []):
        for item in section.get("items", []):
            url = item["url"]
            position += 1
            if not url.endswith(("/", ".html")):
                continue  # llms.txt / docs.json machine manifests
            src = url.strip("/")
            rel = f"{src}/index.md" if url.endswith("/") else src.rsplit(".", 1)[0] + ".md"
            out.append((url, rel, section["title"], position))
    return out


def build() -> dict:
    nav = nav_pages()
    # Section blocks follow nav.yml's section order; inside a block pages
    # sort by their `order` front-matter key (nav position breaks any tie).
    # That is exactly the order the sidebar and the pager render.
    section_index: dict[str, int] = {}
    for _url, _rel, section_title, _pos in nav:
        section_index.setdefault(section_title, len(section_index))

    entries: list[tuple[int, int, int, dict]] = []
    for url, rel, section_title, position in nav:
        path = DOCS / rel
        if not path.exists():
            sys.exit(
                f"build_search: {rel} (nav {url}) is missing — run "
                "tools/sync_site_docs.py first"
            )
        fm, body = read_front_matter(path)
        if not fm.get("title"):
            continue
        page = {
            "url": url,
            "title": str(fm.get("title", "")).strip(),
            "description": str(fm.get("description", "")).strip(),
            "category": str(fm.get("category", "")),
            "order": fm.get("order", 0),
            "section": section_title,
            "sections": parse_page(body),
        }
        entries.append((section_index[section_title], page["order"], position, page))

    entries.sort(key=lambda e: (e[0], e[1], e[2]))
    return {"generated": GENERATED, "pages": [e[3] for e in entries]}


def main() -> int:
    index = build()
    OUT_PATH.write_text(
        json.dumps(index, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    total = len(index["pages"])
    sections = sum(len(p["sections"]) for p in index["pages"])
    print(
        f"build_search: wrote {OUT_PATH.name} — "
        f"{total} pages, {sections} sections"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
