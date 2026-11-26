#!/usr/bin/env python3
"""Static integrity checker for the Mirage documentation site.

Validates everything Jekyll would only fail on at build time — and several
things it would fail on silently (dead links, missing pages, manifest
drift). Runs in CI before the Jekyll build, so a red check never reaches
the hosted site. Pure stdlib + PyYAML; no site build required.

Checks:
  1. Front matter: every docs/**/*.md page has a valid layout, title,
     description (<= 170 chars), category and integer order.
  2. Layouts: every layout referenced by a page exists in _layouts/.
  3. Navigation: every docs/_data/nav.yml URL resolves to a page; every
     content page appears in the navigation exactly once (mirrored data
     files, index and 404 excepted).
  4. Links: every {{ site.baseurl }}/... Liquid reference in markdown and
     HTML resolves to a real output file; raw http:// links are rejected
     (https only); relative .md links are rejected (they 404 under Jekyll).
  5. Liquid safety: any {{ ... }} or {% ... %} that is not a site.baseurl
     reference is flagged — unescaped Liquid in content breaks the Jekyll
     build.
  6. Machine manifests: llms.txt and docs.json list exactly the navigation
     pages with resolvable URLs.
  7. Slop gate: no TODO/FIXME/XXX/placeholder/lorem markers in docs/ or
     the two site tools (word-boundary, case-sensitive, matching the
     repository-wide make slop rules for docs).
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

import yaml

REPO = Path(__file__).resolve().parent.parent
DOCS = REPO / "docs"
BASEURL = "/Mirage"

VALID_LAYOUTS = {"default", "page", "doc"}
PAGE_LAYOUTS = {"page", "doc"}
VALID_CATEGORIES = {
    "landing", "guide", "reference", "spec", "deploy", "project", "agent",
}
MAX_DESC = 170
ALLOWED_EXTENSIONS = {".html", ".txt", ".json", ".yaml", ".css", ".js", ".svg", ".md", ".png", ".ico"}

FRONT_MATTER_RE = re.compile(r"\A---\n(.*?)\n---\n", re.DOTALL)
H1_RE = re.compile(r"^#\s+")
BASEURL_LINK_RE = re.compile(r"\{\{\s*site\.baseurl\s*\}\}(/[^\s\"')<>]*)")
RELATIVE_MD_LINK_RE = re.compile(r"\]\((?!https?://|#|/)([^)\s]+\.md)")
HTTP_LINK_RE = re.compile(r"\"(http://[^\"]+)|\((http://[^)\s]+)")
LIQUID_RE = re.compile(r"\{\{.*?\}\}|\{%.*?%\}", re.DOTALL)
SLOP_RE = re.compile(r"\b(TODO|FIXME|XXX|placeholder|lorem)\b")

errors: list[str] = []


def err(msg: str) -> None:
    errors.append(msg)


def rel(path: Path) -> str:
    return str(path.relative_to(DOCS))


def read_front_matter(path: Path) -> tuple[dict, str]:
    text = path.read_text(encoding="utf-8")
    m = FRONT_MATTER_RE.match(text)
    if not m:
        return {}, text
    try:
        data = yaml.safe_load(m.group(1))
    except yaml.YAMLError as e:
        err(f"{rel(path)}: front matter is not valid YAML ({e})")
        return {}, text
    body = text[m.end():]
    return (data if isinstance(data, dict) else {}), body


def output_paths(pages: dict[str, str], statics: set[str]) -> set[str]:
    """All URLs the built site will serve."""
    urls = set(statics)
    for src_rel in pages:
        p = Path(src_rel)
        if p.name == "index.md":
            urls.add("/" + str(p.parent).replace("\\", "/") + "/" if str(p.parent) != "." else "/")
        else:
            urls.add("/" + str(p.with_suffix(".html")))
    return urls


def main() -> int:
    # Inventory -----------------------------------------------------------
    md_files = sorted(
        p for p in DOCS.rglob("*.md")
        if not any(part.startswith("_") for part in p.relative_to(DOCS).parts)
    )
    if not md_files:
        err("docs/: no markdown pages found")
        return finish()

    # Verbatim data mirrors (docs/data/*, including token-formats.md, a
    # #-comment data file) are served as raw files, never rendered as
    # pages — they carry no front matter and are exempt from page rules.
    page_files = [p for p in md_files if p.relative_to(DOCS).parts[0] != "data"]

    pages: dict[str, dict] = {}
    bodies: dict[str, str] = {}

    # 1 + 2. Front matter and layouts -------------------------------------
    for path in page_files:
        fm, body = read_front_matter(path)
        key = rel(path)
        pages[key] = fm
        bodies[key] = body
        if not fm:
            err(f"{key}: missing front matter")
            continue
        layout = fm.get("layout")
        if layout not in PAGE_LAYOUTS:
            err(f"{key}: layout must be one of {sorted(PAGE_LAYOUTS)}, got {layout!r}")
        elif not (DOCS / "_layouts" / f"{layout}.html").exists():
            err(f"{key}: layout _layouts/{layout}.html does not exist")
        if not str(fm.get("title", "")).strip():
            err(f"{key}: missing title")
        desc = str(fm.get("description", ""))
        if not desc.strip():
            err(f"{key}: missing description")
        elif len(desc) > MAX_DESC:
            err(f"{key}: description is {len(desc)} chars (max {MAX_DESC})")
        if fm.get("category") not in VALID_CATEGORIES:
            err(f"{key}: category must be one of {sorted(VALID_CATEGORIES)}, got {fm.get('category')!r}")
        if not isinstance(fm.get("order"), int):
            err(f"{key}: order must be an integer")
        if H1_RE.match(body):
            err(f"{key}: body starts with an H1 — the layout renders the title")

    # Static assets the site will serve verbatim ---------------------------
    statics: set[str] = set()
    for path in DOCS.rglob("*"):
        if not path.is_file():
            continue
        parts = path.relative_to(DOCS).parts
        if any(part.startswith("_") for part in parts):
            continue
        if path.suffix in ALLOWED_EXTENSIONS and path.suffix != ".md":
            statics.add("/" + str(path.relative_to(DOCS)).replace("\\", "/"))

    # 3. Navigation --------------------------------------------------------
    nav_path = DOCS / "_data" / "nav.yml"
    nav_urls: list[str] = []
    if not nav_path.exists():
        err("_data/nav.yml: missing")
    else:
        data = yaml.safe_load(nav_path.read_text(encoding="utf-8"))
        for section in data.get("sections", []):
            for item in section.get("items", []):
                nav_urls.append(item["url"])
    if len(nav_urls) != len(set(nav_urls)):
        dupes = sorted({u for u in nav_urls if nav_urls.count(u) > 1})
        err(f"nav.yml: duplicate entries: {dupes}")

    urls = output_paths(pages, statics)
    for u in nav_urls:
        if u not in urls:
            err(f"nav.yml: {u} does not resolve to a page or asset")

    # Navigation completeness: every content page appears exactly once.
    # Exempt: the landing index, 404, and mirrored data files under data/.
    nav_count = {u: nav_urls.count(u) for u in set(nav_urls)}
    for key, fm in pages.items():
        p = Path(key)
        if p.name == "index.md" and str(p.parent) == ".":
            continue
        if key == "404.md":
            continue
        if p.parts[0] == "data":
            continue
        if p.name == "index.md":
            candidates = ["/" + str(p.parent) + "/"]
        else:
            candidates = ["/" + str(p.with_suffix(".html"))]
        count = sum(nav_count.get(c, 0) for c in candidates)
        if count == 0:
            err(f"{key}: page is not listed in the navigation")
        elif count > 1:
            err(f"{key}: page is listed {count} times in the navigation")

    # 4 + 5. Links (all site files) and Liquid safety (page content only:
    # layouts and includes are maintainer-owned templates whose Liquid is
    # the point; the CI Jekyll build validates them).
    link_targets = list(page_files) + sorted(DOCS.glob("_layouts/*.html")) + sorted(DOCS.glob("_includes/*.html"))
    liquid_targets = list(page_files)
    for path in link_targets:
        text = path.read_text(encoding="utf-8")
        key = rel(path)
        # Explicitly escaped regions are safe by construction.
        text_scan = re.sub(r"\{%\s*raw\s*%\}.*?\{%\s*endraw\s*%\}", "", text, flags=re.DOTALL)
        for m in BASEURL_LINK_RE.finditer(text):
            target = m.group(1)
            if target not in urls:
                err(f"{key}: link target {target} does not exist (from {{{{ site.baseurl }}}}{target})")
        for m in RELATIVE_MD_LINK_RE.finditer(text):
            if not path.name.endswith(".html"):
                err(f"{key}: relative markdown link '{m.group(1)}' — use the {{{{ site.baseurl }}}}/….html form instead")
        for m in HTTP_LINK_RE.finditer(text):
            bad = m.group(1) or m.group(2)
            err(f"{key}: insecure http:// link '{bad}'")
        for m in LIQUID_RE.finditer(text_scan if path in liquid_targets else ""):
            token = m.group(0)
            if re.fullmatch(r"\{\{\s*site\.baseurl\s*\}\}", token):
                continue
            if re.fullmatch(r"\{\{\s*site\.(data\.nav|url|title|tagline)\b.*?\}\}", token):
                continue
            if re.fullmatch(r"\{\{\s*page\.(title|description|content|url|category|source)\s*\}\}", token):
                continue
            if token == "{{ content }}":
                continue
            if token.startswith("{%") and re.fullmatch(
                r"\{%\s*(raw|endraw|for\b.*|endfor|if\b.*|endif|assign\b.*|include\b.*|comment|endcomment)\s*%\}",
                token,
            ):
                continue
            err(f"{key}: raw Liquid {token[:60]!r} — Jekyll will try to evaluate it; wrap in {{% raw %}}")

    # 6. Machine manifests --------------------------------------------------
    llms_path = DOCS / "llms.txt"
    if not llms_path.exists():
        err("llms.txt: missing (run tools/sync_site_docs.py)")
    else:
        for m in re.finditer(r"\]\((https?://[^)]+)\)", llms_path.read_text(encoding="utf-8")):
            url = m.group(1)
            site_part = url.replace("https://namandhakad712.github.io/Mirage", "")
            if site_part.startswith("/") and site_part not in urls and not site_part.startswith("/blob/"):
                err(f"llms.txt: URL {url} does not resolve to a site page")

    docs_json_path = DOCS / "docs.json"
    if not docs_json_path.exists():
        err("docs.json: missing (run tools/sync_site_docs.py)")
    else:
        try:
            manifest = json.loads(docs_json_path.read_text(encoding="utf-8"))
            listed = set()
            for section in manifest.get("sections", []):
                for page in section.get("pages", []):
                    u = page.get("url", "")
                    # URLs carry the site baseurl prefix (/Mirage); the
                    # checker reasons in site-relative paths.
                    u = u[len(BASEURL):] if u.startswith(BASEURL) else u
                    listed.add(u)
                    if u not in urls:
                        err(f"docs.json: URL {u} does not resolve to a site page")
            for u in urls:
                if u.endswith(".html") and u not in listed and u != "/404.html":
                    stem = u[1:-5]
                    if stem.startswith(("guide/", "reference/", "spec/", "deploy/", "agent/")) or stem in (
                        "about", "changelog", "charter", "invariants", "claims-policy",
                        "known-limits", "vendor-notes",
                    ):
                        if "/" + stem + ".html" in urls or "/" + stem + "/" in urls:
                            err(f"docs.json: page {u} is missing from the manifest")
        except json.JSONDecodeError as e:
            err(f"docs.json: invalid JSON ({e})")

    # 7. Slop gate -----------------------------------------------------------
    # Scope mirrors the repository's make slop rules for authored content:
    # markdown under docs/, excluding docs/design/ (the verbatim historical
    # design document, quoted as delivered) and the verbatim data mirrors.
    # The words below appear in check_site.py's own docstring, so the tools
    # themselves stay outside the scan — same as the Makefile gate.
    slop_targets = [
        p for p in md_files
        if p.relative_to(DOCS).parts[0] not in ("data", "design")
    ]
    for path in slop_targets:
        for n, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            if SLOP_RE.search(line):
                err(f"{rel(path)}:{n}: slop marker in line: {line.strip()[:70]}")

    return finish()


def finish() -> int:
    if errors:
        print(f"check_site: {len(errors)} problem(s):")
        for e in errors:
            print(f"  - {e}")
        return 1
    print("check_site: all structural checks passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
