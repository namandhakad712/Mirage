#!/usr/bin/env python3
"""Sync the documentation site's mirrored content and machine manifests.

The normative sources live outside docs/ (spec/, data/, README.md,
CHANGELOG.md). The hosted site (docs/) carries generated mirrors so the
whole guide is readable in one place. This script keeps those mirrors and
the machine-readable manifests (llms.txt, llms-full.txt, docs.json)
regenerated and byte-stable:

  spec/SIGNALS.md                    -> docs/spec/SIGNALS.md (+ front matter)
  spec/ADAPTER-PROTOCOL.md           -> docs/spec/ADAPTER-PROTOCOL.md
  spec/DECOY-CATALOG.md              -> docs/spec/DECOY-CATALOG.md
  spec/golden-vectors/HAND-COMPUTED.md -> docs/spec/golden-vectors/...
  spec/golden-vectors/*.json         -> verbatim copies
  spec/decoy-catalog/catalog.yaml    -> verbatim copy
  data/*.txt                         -> verbatim copies under docs/data/
  data/token-formats.md              -> docs/data/token-formats.md (+ front matter)
  README.md                          -> docs/about.md
  CHANGELOG.md                       -> docs/changelog.md

Markdown mirrors: the leading H1 is dropped (the layout renders the front
matter title), front matter is injected, and a `source:` key records the
origin so the page shows a synced-from banner.

Modes:
  default  write only the files whose content would change
  --check  write nothing; exit 1 with a report if anything is stale

Determinism: no timestamps, no environment-dependent output — a clean tree
syncs to a byte-identical tree. CI runs --check on every push and pull
request, so drift is impossible to merge.
"""

from __future__ import annotations

import argparse
import json
import posixpath
import re
import sys
from pathlib import Path

import yaml

REPO = Path(__file__).resolve().parent.parent
DOCS = REPO / "docs"

SITE_URL = "https://namandhakad712.github.io"
BASEURL = "/Mirage"
SITE_NAME = "Mirage"
SITE_TAGLINE = "Deception-layer defense against AI-driven attack agents"
SITE_DESCRIPTION = (
    "Mirage is an open-source deception layer: every request is scored by "
    "deterministic signals, attackers are routed into decoy personas, and "
    "the whole system fails open by design."
)
SPEC_VERSION = "1.1.0"
PROTOCOL_VERSION = "1"
LICENSE = "AGPL-3.0"
REPO_URL = "https://github.com/namandhakad712/Mirage"

H1_RE = re.compile(r"^#\s+.+?\n+")
FRONT_MATTER_RE = re.compile(r"\A---\n.*?\n---\n", re.DOTALL)

# Markdown mirrors: (source, destination, title, description, category, order).
# Bodies are link-rewritten (relative repo links -> site pages or GitHub
# URLs) and Liquid-escaped ({{SEED:…}} examples survive the Jekyll build).
MD_MIRRORS = [
    (
        "spec/SIGNALS.md",
        "spec/SIGNALS.md",
        "Signal Specification",
        "SIGNALS v1.1.0 — the eleven signals, fixed weights and classes, "
        "gating rules, evaluation order and the verdict ladder.",
        "spec",
        1,
    ),
    (
        "spec/ADAPTER-PROTOCOL.md",
        "spec/ADAPTER-PROTOCOL.md",
        "Adapter Protocol",
        "The v1 contract between an edge adapter and Mirage Core: the "
        "request, the decision, the action set and the event.",
        "spec",
        2,
    ),
    (
        "spec/DECOY-CATALOG.md",
        "spec/DECOY-CATALOG.md",
        "Decoy Catalog",
        "The v1 decoy catalog format: personas, entries, leads, tokens, "
        "reserved values and validation rules.",
        "spec",
        3,
    ),
    (
        "spec/golden-vectors/HAND-COMPUTED.md",
        "spec/golden-vectors/HAND-COMPUTED.md",
        "Golden Vectors — Hand Computed",
        "The arithmetic behind all 20 golden vector cases, computed by "
        "hand and cross-checked by tools/gen_vectors.py.",
        "spec",
        4,
    ),
    (
        "README.md",
        "about.md",
        "About",
        "What Mirage is, what runs today, and where the repository's "
        "honest status line stands — the README, unedited.",
        "project",
        1,
    ),
    (
        "CHANGELOG.md",
        "changelog.md",
        "Changelog",
        "Every notable change to Mirage, round by round, following Keep a "
        "Changelog.",
        "project",
        2,
    ),
]

# Byte-verbatim mirrors: (source, destination). data/token-formats.md is
# a #-comment data file, not a document — it stays verbatim like the .txt
# lists and is linked as a raw file, never rendered as a page.
RAW_MIRRORS = [
    ("spec/decoy-catalog/catalog.yaml", "spec/decoy-catalog/catalog.yaml"),
    ("spec/golden-vectors/vectors.json", "spec/golden-vectors/vectors.json"),
    ("spec/golden-vectors/renders.json", "spec/golden-vectors/renders.json"),
    ("data/scanner-paths.txt", "data/scanner-paths.txt"),
    ("data/ua-suspicious.txt", "data/ua-suspicious.txt"),
    ("data/ua-verified-bots.txt", "data/ua-verified-bots.txt"),
    ("data/reserved-hosts.txt", "data/reserved-hosts.txt"),
    ("data/reason-texts.txt", "data/reason-texts.txt"),
    ("data/token-formats.md", "data/token-formats.md"),
]


def strip_leading_h1(text: str) -> str:
    """Drop a leading H1 (and any front matter) — the layout renders the title."""
    text = FRONT_MATTER_RE.sub("", text)
    return H1_RE.sub("", text, count=1)


# --------------------------------------------------------------------------
# Link rewriting and Liquid escaping
#
# Mirrored bodies keep their repository-relative markdown links, which are
# correct on github.com and wrong under Jekyll. rewrite_links maps them to
# site pages (when the target is one) or to GitHub blob/tree URLs (when it
# is a repository file); escape_liquid then wraps every remaining Liquid
# token ({{SEED:…}} format slots in the changelog, worker template examples)
# in {% raw %} so the Jekyll build renders them verbatim.
# --------------------------------------------------------------------------

MD_LINK_RE = re.compile(r"\]\(([^)\s]+)\)")
LIQUID_TOKEN_RE = re.compile(r"\{\{.*?\}\}|\{%.*?%\}", re.DOTALL)
SAFE_LIQUID_RE = re.compile(r"\{\{\s*site\.baseurl\s*\}\}")
RAW_TAG_RE = re.compile(r"\{%\s*(raw|endraw)\s*%\}")


def site_url_map() -> dict[str, str]:
    """Every file under docs/ mapped to the URL the built site serves.

    Merged with the mirror destinations this run will produce, so link
    resolution is identical on a cold bootstrap and on a re-run (a mirror
    referenced before it exists on disk still resolves).
    """
    urls: dict[str, str] = {}
    # Synthetic entries for the mirrors generated by this script.
    for _, dst, *_rest in MD_MIRRORS:
        urls[dst] = "/" + dst[: -len(".md")] + ".html"
    for _, dst in RAW_MIRRORS:
        urls[dst] = "/" + dst
    # Everything already on disk.
    for path in sorted(DOCS.rglob("*")):
        if not path.is_file():
            continue
        rel = path.relative_to(DOCS).as_posix()
        if any(part.startswith("_") for part in path.relative_to(DOCS).parts):
            continue
        if path.name == "index.md":
            urls[rel] = "/" + (posixpath.dirname(rel) + "/" if posixpath.dirname(rel) else "/")
        elif path.suffix == ".md":
            urls[rel] = "/" + rel[: -len(".md")] + ".html"
        else:
            urls[rel] = "/" + rel
    return urls


SITE_URLS = site_url_map()


def resolve_link(src_rel: str, link: str) -> str | None:
    """Rewrite one relative markdown link target, or None to leave it."""
    if link.startswith(("http://", "https://", "#", "mailto:", "{{", "/")):
        return None
    anchor = ""
    if "#" in link:
        link, _, anchor = link.partition("#")
        anchor = "#" + anchor
    if not link:
        return None
    base = posixpath.dirname(src_rel)
    target = posixpath.normpath(posixpath.join(base, link)) if base else posixpath.normpath(link)
    # Links written from inside docs/ can escape it ("../../CHANGELOG.md"
    # from docs/adr/); docs/ sits at the repository root, so each leading
    # "../" just steps out of it.
    while target.startswith("../"):
        target = target[3:]
    for cand in (target, target[len("docs/"):] if target.startswith("docs/") else target):
        if cand in SITE_URLS:
            return "{{ site.baseurl }}" + SITE_URLS[cand] + anchor
    repo_path = REPO / target
    if repo_path.exists():
        kind = "tree" if repo_path.is_dir() else "blob"
        return f"{REPO_URL}/{kind}/main/{target}{anchor}"
    return None


def rewrite_links(src_rel: str, body: str) -> str:
    def repl(m: re.Match) -> str:
        resolved = resolve_link(src_rel, m.group(1))
        return f"]({resolved})" if resolved else m.group(0)

    return MD_LINK_RE.sub(repl, body)


def escape_liquid(text: str) -> str:
    """Wrap every non-baseurl Liquid token in raw tags, idempotently."""
    # Unwrap existing raw blocks first, so a re-run never double-wraps.
    text = re.sub(r"\{%\s*raw\s*%\}(.*?)\{%\s*endraw\s*%\}", r"\1", text, flags=re.DOTALL)

    def repl(m: re.Match) -> str:
        token = m.group(0)
        if SAFE_LIQUID_RE.fullmatch(token):
            return token
        return "{% raw %}" + token + "{% endraw %}"

    return LIQUID_TOKEN_RE.sub(repl, text)


def front_matter(title: str, description: str, category: str, order: int, source: str) -> str:
    return (
        "---\n"
        f'layout: doc\n'
        f'title: "{title}"\n'
        f'description: "{description}"\n'
        f"category: {category}\n"
        f"order: {order}\n"
        f"source: {source}\n"
        "---\n"
    )


def mirror_markdown(src_rel: str) -> str:
    """Read a source markdown file and produce the mirrored page body."""
    src = (REPO / src_rel).read_text(encoding="utf-8")
    body = strip_leading_h1(src)
    body = rewrite_links(src_rel, body)
    return escape_liquid(body).rstrip("\n") + "\n"


def nav_sections() -> list[dict]:
    """The site navigation, as parsed from docs/_data/nav.yml."""
    data = yaml.safe_load((DOCS / "_data" / "nav.yml").read_text(encoding="utf-8"))
    return data["sections"]


def page_url_to_path(url: str) -> str:
    """Map a site URL (nav item) to its docs/ file path (no leading slash)."""
    if url.endswith("/"):
        return url.strip("/") + "/index.md"
    return url.strip("/").rsplit(".", 1)[0] + ".md"


def collect_pages(generated: dict[str, str] | None = None) -> list[dict]:
    """All pages referenced by the navigation, with front matter loaded.

    Front matter is read from the in-memory generated set first (mirrors
    this run produces), then from disk, then from the nav item itself —
    so the manifests are identical on a cold bootstrap and on a re-run.
    """
    generated = generated or {}
    pages = []
    for section in nav_sections():
        for item in section["items"]:
            rel = page_url_to_path(item["url"])
            if rel in generated:
                fm = front_matter_of(generated[rel])
            else:
                fm = read_front_matter(DOCS / rel)
            pages.append(
                {
                    "section": section["title"],
                    "section_id": section["id"],
                    "nav_title": item["title"],
                    "url": item["url"],
                    "title": fm.get("title") or item["title"],
                    "description": fm.get("description") or item.get("description", ""),
                    "path": rel,
                }
            )
    return pages


def front_matter_of(text: str) -> dict:
    m = FRONT_MATTER_RE.match(text)
    if not m:
        return {}
    try:
        parsed = yaml.safe_load(m.group(0)[4:-4])
    except yaml.YAMLError:
        return {}
    return parsed if isinstance(parsed, dict) else {}


def read_front_matter(path: Path) -> dict:
    if not path.exists():
        # Mirrors generated by this very script (spec pages) may not exist
        # yet on a first run; callers fall back to their nav metadata.
        return {}
    text = path.read_text(encoding="utf-8")
    m = FRONT_MATTER_RE.match(text)
    if not m:
        return {}
    parsed = yaml.safe_load(m.group(0)[4:-4])
    return parsed if isinstance(parsed, dict) else {}


def render_llms_txt(pages: list[dict]) -> str:
    lines = [
        f"# {SITE_NAME}",
        "",
        f"> {SITE_DESCRIPTION}",
        "",
        f"Repository: {REPO_URL} · License: {LICENSE} · "
        f"Signal spec v{SPEC_VERSION} · Adapter protocol v{PROTOCOL_VERSION}.",
        "",
    ]
    by_section: dict[str, list[dict]] = {}
    for p in pages:
        by_section.setdefault(p["section"], []).append(p)
    for section, items in by_section.items():
        lines.append(f"## {section}")
        lines.append("")
        for p in items:
            lines.append(
                f"- [{p['title']}]({SITE_URL}{BASEURL}{p['url']}): {p['description']}"
            )
        lines.append("")
    lines += [
        "## Machine surface",
        "",
        f"- [llms.txt]({SITE_URL}{BASEURL}/llms.txt): this index.",
        f"- [llms-full.txt]({SITE_URL}{BASEURL}/llms-full.txt): every page "
        "above, flattened into one document.",
        f"- [docs.json]({SITE_URL}{BASEURL}/docs.json): structured manifest "
        "(sections, titles, descriptions, paths).",
        f"- [Golden vectors]({REPO_URL}/blob/main/spec/golden-vectors/"
        "vectors.json): 20 hand-computed cases that lock the decision "
        "arithmetic — the executable contract.",
        "",
    ]
    return "\n".join(lines)


def render_llms_full(pages: list[dict], generated: dict[str, str]) -> str:
    parts = [
        f"# {SITE_NAME} — full documentation",
        "",
        f"> {SITE_DESCRIPTION}",
        "",
        f"Source of truth: {REPO_URL}. This file is generated; edit the "
        "pages under docs/ in the repository.",
        "",
    ]
    for p in pages:
        rel = p["path"]
        if rel in generated:
            body = strip_leading_h1(generated[rel])
        elif (DOCS / rel).exists():
            body = strip_leading_h1((DOCS / rel).read_text(encoding="utf-8"))
        else:
            continue  # a mirror that is being generated this run but is
            # referenced only by the nav (e.g. data assets) — nothing to embed
        parts.append("=" * 78)
        parts.append(f"# {p['title']}")
        parts.append("")
        parts.append(f"> {p['description']}")
        parts.append(f"Source: {rel} — {SITE_URL}{BASEURL}{p['url']}")
        parts.append("")
        parts.append(body.strip("\n"))
        parts.append("")
    return "\n".join(parts)


def render_docs_json(pages: list[dict]) -> str:
    by_section: dict[str, list[dict]] = {}
    for p in pages:
        by_section.setdefault(p["section"], []).append(p)
    manifest = {
        "name": SITE_NAME,
        "tagline": SITE_TAGLINE,
        "description": SITE_DESCRIPTION,
        "url": f"{SITE_URL}{BASEURL}",
        "repository": REPO_URL,
        "license": LICENSE,
        "spec_version": SPEC_VERSION,
        "protocol_version": PROTOCOL_VERSION,
        "sections": [
            {
                "id": sid,
                "title": section,
                "pages": [
                    {
                        "title": p["title"],
                        "description": p["description"],
                        "path": p["path"],
                        "url": f"{BASEURL}{p['url']}",
                    }
                    for p in by_section.get(section, [])
                ],
            }
            for sid, section in [
                (s["id"], s["title"]) for s in nav_sections()
            ]
        ],
    }
    return json.dumps(manifest, indent=2, ensure_ascii=False) + "\n"


def build_all() -> dict[str, str]:
    """Every generated file, as {relative path under docs/: content}."""
    out: dict[str, str] = {}
    for src_rel, dst_rel, title, desc, category, order in MD_MIRRORS:
        fm = front_matter(title, desc, category, order, src_rel)
        out[dst_rel] = fm + mirror_markdown(src_rel)
    for src_rel, dst_rel in RAW_MIRRORS:
        out[dst_rel] = (REPO / src_rel).read_text(encoding="utf-8")

    pages = collect_pages(out)
    out["llms.txt"] = render_llms_txt(pages)
    out["llms-full.txt"] = render_llms_full(pages, out)
    out["docs.json"] = render_docs_json(pages)
    return out


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument(
        "--check",
        action="store_true",
        help="verify the tree is in sync; exit 1 with a report if not",
    )
    args = parser.parse_args()

    generated = build_all()
    stale: list[str] = []
    missing: list[str] = []

    for rel, content in sorted(generated.items()):
        target = DOCS / rel
        if not target.exists():
            missing.append(rel)
            continue
        if target.read_text(encoding="utf-8") != content:
            stale.append(rel)

    if args.check:
        problems = missing + stale
        if problems:
            print("sync_site_docs: out of date:")
            for rel in missing:
                print(f"  missing: docs/{rel}")
            for rel in stale:
                print(f"  stale:   docs/{rel}")
            print("regenerate with: python3 tools/sync_site_docs.py")
            return 1
        print(f"sync_site_docs: {len(generated)} generated files in sync")
        return 0

    changed = 0
    for rel in missing + stale:
        target = DOCS / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        (DOCS / rel).write_text(generated[rel], encoding="utf-8")
        print(f"sync_site_docs: wrote docs/{rel}")
        changed += 1
    if not changed:
        print(f"sync_site_docs: {len(generated)} generated files already in sync")
    return 0


if __name__ == "__main__":
    sys.exit(main())
