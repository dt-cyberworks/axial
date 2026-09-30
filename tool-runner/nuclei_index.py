#!/usr/bin/env python3
"""Template index for evidence-driven nuclei selection (REQ-PIPE-004).

Built once at image build time from the baked templates (stdlib only: the
runner has no PyYAML and the format needed here is a handful of lines of each
template's `info:` block). The index holds exactly the templates the former
single main pass would have run, i.e. carrying one of the selection tags, none
of the excluded tags or ids, and living outside the port-bound `network/` and
`javascript/` directories that never apply to a web surface.

The worker never passes a template path. It names a *selection* - a group
(`generic`, `products`, `all`), an optional shard and a list of product keys -
and this program resolves it against the index at run time, so the set of
templates that can be selected is fixed by the image, not by the caller.

    nuclei_index.py build <templates_root> <out.json> [--version TAG]
    nuclei_index.py summary [--index FILE]
    nuclei_index.py select --group generic|products|all [--shard K/N]
                           [--products a,b] [--out FILE] [--index FILE]
"""

from __future__ import annotations

import argparse
import json
import math
import os
import re
import sys

TEMPLATES_ROOT = "/opt/nuclei-templates"
INDEX_PATH = "/opt/nuclei-index.json"
SCHEMA = 1

# The former single main pass (worker tool_runner_client._ALL_TAGS, -etags, -eid).
# A worker test keeps these identical to the worker's flags.
SELECTION_TAGS = frozenset({"cve", "misconfig", "exposure", "exposures", "default-login", "waf", "dast"})
EXCLUDED_TAGS = frozenset({"intrusive", "dos", "fuzz", "csp-bypass"})
EXCLUDED_IDS = frozenset({"waf-detect", "http-missing-security-headers"})
# REQ-PIPE-004: port-bound protocol templates never run against a web surface.
NEVER_ON_WEB_DIRS = frozenset({"network", "javascript"})

GROUPS = ("generic", "products", "all")
MAX_PRODUCTS = 24
_KEY_RE = re.compile(r"^[a-z0-9][a-z0-9_.+-]{0,39}$")
_SHARD_RE = re.compile(r"^([1-9][0-9]?)/([1-9][0-9]?)$")
_MAX_SHARDS = 64


def normalize_key(value: str) -> str:
    """`Nextcloud Server` -> `nextcloud_server`; empty stays empty."""
    return re.sub(r"[^a-z0-9.+]+", "_", str(value or "").strip().strip("'\"").lower()).strip("_")


def _split_tags(raw: str) -> list[str]:
    raw = raw.strip()
    if raw.startswith("[") and raw.endswith("]"):
        raw = raw[1:-1]
    return [t.strip().strip("'\"").lower() for t in raw.split(",") if t.strip()]


def parse_template(text: str) -> dict | None:
    """id, severity, tags, vendor, product and max-request of one template.

    Line based on purpose: it needs four keys of the `info:` block and nothing
    else. Returns None when the file has no id or no info block.
    """
    template_id = None
    info: list[str] = []
    in_info = False
    for line in text.splitlines():
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        if not line.startswith((" ", "\t")):
            in_info = line.rstrip() == "info:"
            match = re.match(r"^id:\s*(\S+)", line)
            if match and template_id is None:
                template_id = match.group(1).strip("'\"")
            continue
        if in_info:
            info.append(line.rstrip())
    if not template_id or not info:
        return None

    severity, tags, vendor, product, max_request = "", [], "", "", 0
    in_metadata = False
    in_tag_list = False
    for line in info:
        indent = len(line) - len(line.lstrip())
        stripped = line.strip()
        if in_tag_list:
            if stripped.startswith("- "):
                tags.append(stripped[2:].strip().strip("'\"").lower())
                continue
            in_tag_list = False
        if indent <= 2:
            in_metadata = stripped == "metadata:"
            if stripped.startswith("severity:"):
                severity = stripped.split(":", 1)[1].strip().lower()
            elif stripped.startswith("tags:"):
                value = stripped.split(":", 1)[1]
                if value.strip():
                    tags = _split_tags(value)
                else:
                    in_tag_list = True
            continue
        if in_metadata:
            if stripped.startswith("vendor:"):
                vendor = normalize_key(stripped.split(":", 1)[1])
            elif stripped.startswith("product:"):
                product = normalize_key(stripped.split(":", 1)[1])
            elif stripped.startswith("max-request:"):
                try:
                    max_request = int(stripped.split(":", 1)[1].strip())
                except ValueError:
                    max_request = 0
    return {"id": template_id, "severity": severity, "tags": tags, "vendor": vendor,
            "product": product, "max_request": max_request}


def is_selected(rel_path: str, meta: dict) -> bool:
    """Would the former single main pass have run this template on a web surface?"""
    top = rel_path.split("/", 1)[0]
    if top in NEVER_ON_WEB_DIRS:
        return False
    tags = set(meta["tags"])
    if meta["id"] in EXCLUDED_IDS or tags & EXCLUDED_TAGS:
        return False
    return bool(tags & SELECTION_TAGS)


def build_index(root: str = TEMPLATES_ROOT, version: str = "") -> dict:
    rows: list[list] = []
    skipped = 0
    for directory, _dirs, files in os.walk(root):
        for name in files:
            if not name.endswith(".yaml"):
                continue
            path = os.path.join(directory, name)
            rel = os.path.relpath(path, root).replace(os.sep, "/")
            try:
                with open(path, encoding="utf-8", errors="replace") as handle:
                    meta = parse_template(handle.read())
            except OSError:
                skipped += 1
                continue
            if meta is None:
                skipped += 1
                continue
            if is_selected(rel, meta):
                rows.append([rel, meta["id"], meta["severity"], ",".join(meta["tags"]),
                             meta["vendor"], meta["product"], meta["max_request"]])
    rows.sort(key=lambda r: r[0])
    return {"schema": SCHEMA, "templates_version": version, "root": root, "unparsed": skipped, "t": rows}


def _bound(row: list) -> bool:
    return bool(row[4] or row[5])


def matches_products(row: list, keys: set[str]) -> bool:
    """A product-bound template applies to a surface whose profile holds one of
    `keys`: its product equals (or is a `<key>_...` variant of) a key, one of its
    tags is a key, or - with no product of its own - its vendor is a key."""
    if not _bound(row):
        return False
    product, vendor, tags = row[5], row[4], set(row[3].split(","))
    if tags & keys:
        return True
    if product:
        return any(product == k or product.startswith(k + "_") for k in keys)
    return vendor in keys


def parse_shard(shard: str | None) -> tuple[int, int]:
    if not shard:
        return 1, 1
    match = _SHARD_RE.match(shard)
    if not match:
        raise ValueError("invalid shard")
    k, n = int(match.group(1)), int(match.group(2))
    if not 1 <= k <= n <= _MAX_SHARDS:
        raise ValueError("invalid shard")
    return k, n


def parse_products(raw) -> set[str]:
    keys = [str(k).strip() for k in (raw.split(",") if isinstance(raw, str) else raw or []) if str(k).strip()]
    if len(keys) > MAX_PRODUCTS or not all(_KEY_RE.match(k) for k in keys):
        raise ValueError("invalid products")
    return set(keys)


def select(index: dict, group: str, shard: str | None = None, products=None) -> list[str]:
    """Relative template paths of one selection, sorted, one shard of N."""
    if group not in GROUPS:
        raise ValueError("invalid group")
    k, n = parse_shard(shard)
    keys = parse_products(products)
    rows = index["t"]
    if group == "generic":
        chosen = [r for r in rows if not _bound(r)]
    elif group == "products":
        if not keys:
            return []
        chosen = [r for r in rows if matches_products(r, keys)]
    else:
        chosen = list(rows)
    return [r[0] for i, r in enumerate(chosen) if i % n == k - 1]


def summary(index: dict) -> dict:
    rows = index["t"]
    generic = sum(1 for r in rows if not _bound(r))
    products: dict[str, int] = {}
    for r in rows:
        if r[5]:
            products[r[5]] = products.get(r[5], 0) + 1
    return {
        "schema": index.get("schema"), "templates_version": index.get("templates_version", ""),
        "total": len(rows), "generic": generic, "bound": len(rows) - generic,
        "products": dict(sorted(products.items())),
    }


def _load(path: str) -> dict:
    with open(path, encoding="utf-8") as handle:
        index = json.load(handle)
    if index.get("schema") != SCHEMA:
        raise ValueError("unsupported index schema")
    return index


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)
    b = sub.add_parser("build")
    b.add_argument("root")
    b.add_argument("out")
    b.add_argument("--version", default="")
    s = sub.add_parser("summary")
    s.add_argument("--index", default=INDEX_PATH)
    c = sub.add_parser("select")
    c.add_argument("--group", required=True)
    c.add_argument("--shard")
    c.add_argument("--products", default="")
    c.add_argument("--out")
    c.add_argument("--index", default=INDEX_PATH)
    args = parser.parse_args(argv)

    if args.command == "build":
        index = build_index(args.root, args.version)
        with open(args.out, "w", encoding="utf-8") as handle:
            json.dump(index, handle, separators=(",", ":"))
        print(json.dumps(summary(index)["total"]))
        return 0
    index = _load(args.index)
    if args.command == "summary":
        print(json.dumps(summary(index), separators=(",", ":")))
        return 0
    try:
        paths = select(index, args.group, args.shard, args.products)
    except ValueError as exc:
        print(f"nuclei_index: {exc}", file=sys.stderr)
        return 2
    absolute = [os.path.join(index["root"], p) for p in paths]
    if args.out:
        with open(args.out, "w", encoding="utf-8") as handle:
            handle.write("\n".join(absolute) + ("\n" if absolute else ""))
    print(json.dumps({"templates": len(absolute)}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
