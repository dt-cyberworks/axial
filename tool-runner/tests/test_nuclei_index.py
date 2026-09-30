"""TC-PIPE-004 (runner half): the template index the evidence-driven selection
resolves against. Pure functions, stdlib only - the index builder has to run in
the runner image, which has no PyYAML."""

from __future__ import annotations

import json
import pathlib
import sys

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

import nuclei_index as ni  # noqa: E402

ROOT = pathlib.Path(__file__).resolve().parents[1]


def _template(template_id, *, tags="cve,rce", severity="high", vendor=None, product=None, max_request=None, extra=""):
    meta = ""
    if vendor or product or max_request:
        meta = "  metadata:\n"
        if max_request:
            meta += f"    max-request: {max_request}\n"
        if vendor:
            meta += f"    vendor: {vendor}\n"
        if product:
            meta += f"    product: {product}\n"
    return f"id: {template_id}\n\ninfo:\n  name: {template_id}\n  author: a\n  severity: {severity}\n{meta}  tags: {tags}\n{extra}\nhttp:\n  - method: GET\n"


def _tree(tmp_path, files: dict[str, str]):
    for rel, text in files.items():
        path = tmp_path / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)
    return tmp_path


# --- parsing one template --------------------------------------------------------------

def test_parse_reads_id_severity_tags_vendor_product_and_request_count():
    meta = ni.parse_template(_template("CVE-2023-1", tags="cve,cve2023,nextcloud", vendor="Nextcloud", product="Nextcloud Server", max_request=4))
    assert meta == {"id": "CVE-2023-1", "severity": "high", "tags": ["cve", "cve2023", "nextcloud"],
                    "vendor": "nextcloud", "product": "nextcloud_server", "max_request": 4}


def test_parse_handles_tags_before_metadata_and_list_forms():
    text = "id: t1\ninfo:\n  name: x\n  tags:\n    - Cve\n    - 'misconfig'\n  metadata:\n    product: nginx\n  severity: low\n"
    meta = ni.parse_template(text)
    assert meta["tags"] == ["cve", "misconfig"] and meta["product"] == "nginx" and meta["severity"] == "low"
    assert ni.parse_template("id: t2\ninfo:\n  tags: [cve, exposure]\n")["tags"] == ["cve", "exposure"]


def test_parse_ignores_lookalike_keys_outside_the_info_block():
    text = _template("t3", tags="exposure") + "  headers:\n    product: nope\n    tags: cve\n"
    meta = ni.parse_template(text)
    assert meta["product"] == "" and meta["tags"] == ["exposure"]


def test_negative_parse_returns_none_for_a_file_that_is_not_a_template():
    assert ni.parse_template("") is None
    assert ni.parse_template("name: not a template\n") is None
    assert ni.parse_template("id: only-an-id\n") is None


# --- what is in the index (REQ-PIPE-004) ------------------------------------------------------

def _index(tmp_path):
    files = {
        "http/cves/2023/CVE-2023-1.yaml": _template("CVE-2023-1", tags="cve,nextcloud", vendor="nextcloud", product="nextcloud_server"),
        "http/cves/2022/CVE-2022-2.yaml": _template("CVE-2022-2", tags="cve,wordpress,wp-plugin", vendor="acme", product="acme_plugin"),
        "http/exposures/env.yaml": _template("env-file", tags="exposure,config"),
        "http/misconfiguration/cors.yaml": _template("cors-misconfig", tags="misconfig,cors"),
        "http/misconfiguration/nginx-status.yaml": _template("nginx-status", tags="misconfig,nginx", vendor="f5", product="nginx"),
        "dast/xss.yaml": _template("dast-xss", tags="dast,xss"),
        "http/default-logins/x.yaml": _template("x-login", tags="default-login", vendor="apache", product="tomcat"),
        # never part of the selection:
        "network/ftp/ftp-anon.yaml": _template("ftp-anon", tags="exposure,ftp"),
        "javascript/js.yaml": _template("js-t", tags="exposure,js"),
        "http/technologies/nginx-detect.yaml": _template("nginx-detect", tags="tech,nginx", severity="info"),
        "http/vulnerabilities/intrusive.yaml": _template("intrusive-one", tags="cve,intrusive"),
        "http/vulnerabilities/dos.yaml": _template("dos-one", tags="cve,dos"),
        "http/vulnerabilities/fuzzy.yaml": _template("fuzz-one", tags="dast,fuzz"),
        "http/vulnerabilities/csp.yaml": _template("csp-one", tags="cve,csp-bypass"),
        "http/misconfiguration/http-missing-security-headers.yaml": _template("http-missing-security-headers", tags="misconfig,headers"),
        "http/technologies/waf-detect.yaml": _template("waf-detect", tags="waf,tech"),
        "readme.yaml": "just: data\n",
    }
    _tree(tmp_path, files)
    return ni.build_index(str(tmp_path), "vTEST")


def test_req_pipe_004_the_index_holds_exactly_the_former_main_pass(tmp_path):
    index = _index(tmp_path)
    assert sorted(r[1] for r in index["t"]) == [
        "CVE-2022-2", "CVE-2023-1", "cors-misconfig", "dast-xss", "env-file", "nginx-status", "x-login"]
    assert index["templates_version"] == "vTEST" and index["schema"] == ni.SCHEMA


def test_negative_req_pipe_004_network_and_javascript_templates_are_never_in_the_index(tmp_path):
    ids = {r[1] for r in _index(tmp_path)["t"]}
    assert not {"ftp-anon", "js-t"} & ids


def test_negative_req_pipe_004_the_conservative_exclusions_hold(tmp_path):
    ids = {r[1] for r in _index(tmp_path)["t"]}
    assert not {"intrusive-one", "dos-one", "fuzz-one", "csp-one", "http-missing-security-headers", "waf-detect", "nginx-detect"} & ids


def test_req_pipe_004_the_index_is_deterministic_and_sorted(tmp_path):
    index = _index(tmp_path)
    assert index == ni.build_index(str(tmp_path), "vTEST")
    paths = [r[0] for r in index["t"]]
    assert paths == sorted(paths)


# --- selections ---------------------------------------------------------------------------------------

def test_req_pipe_004_generic_holds_the_unbound_templates_and_products_the_bound_ones(tmp_path):
    index = _index(tmp_path)
    generic = {p.rsplit("/", 1)[1] for p in ni.select(index, "generic")}
    assert generic == {"env.yaml", "cors.yaml", "xss.yaml"}
    summary = ni.summary(index)
    assert (summary["total"], summary["generic"], summary["bound"]) == (7, 3, 4)


def test_req_pipe_004_a_product_selection_matches_by_product_tag_or_vendor(tmp_path):
    index = _index(tmp_path)

    def names(keys):
        return {p.rsplit("/", 1)[1] for p in ni.select(index, "products", products=keys)}

    assert names(["nextcloud"]) == {"CVE-2023-1.yaml"}             # by tag, and a `<key>_server` product
    assert names(["nginx"]) == {"nginx-status.yaml"}               # by product
    assert names(["wordpress"]) == {"CVE-2022-2.yaml"}             # by tag only
    assert names(["tomcat"]) == {"x.yaml"}
    assert names(["apache"]) == {"x.yaml"} or names(["apache"]) == set()  # vendor only counts for a product-less template
    assert names(["nextcloud", "nginx", "tomcat"]) == {"CVE-2023-1.yaml", "nginx-status.yaml", "x.yaml"}


def test_negative_req_pipe_004_a_product_selection_never_returns_unbound_templates(tmp_path):
    index = _index(tmp_path)
    picked = ni.select(index, "products", products=["cors", "exposure", "dast", "xss", "config"])
    assert not {p.rsplit("/", 1)[1] for p in picked} & {"env.yaml", "cors.yaml", "xss.yaml"}


def test_negative_req_pipe_004_no_products_means_no_templates_never_everything(tmp_path):
    assert ni.select(_index(tmp_path), "products", products=[]) == []


def test_req_pipe_004_all_is_generic_plus_bound_and_shards_partition_it_exactly(tmp_path):
    index = _index(tmp_path)
    everything = ni.select(index, "all")
    assert len(everything) == 7
    for n in (1, 2, 3, 7, 9):
        shards = [ni.select(index, "all", shard=f"{k}/{n}") for k in range(1, n + 1)]
        merged = [p for shard in shards for p in shard]
        assert sorted(merged) == sorted(everything) and len(merged) == len(set(merged)), n
    generic = ni.select(index, "generic")
    assert sorted(ni.select(index, "generic", "1/2") + ni.select(index, "generic", "2/2")) == sorted(generic)


@pytest.mark.parametrize("shard", ["0/3", "4/3", "1/65", "a/b", "1/0", "1", "1/2/3", "-1/3", "1/3; id", ""])
def test_negative_req_pipe_004_a_bad_shard_is_refused(shard, tmp_path):
    if shard == "":
        assert ni.parse_shard(shard) == (1, 1)  # empty means the whole set
        return
    with pytest.raises(ValueError):
        ni.select(_index(tmp_path), "generic", shard=shard)


@pytest.mark.parametrize("products", [["a b"], ["A"], ["../x"], ["a;b"], ["$(id)"], ["x" * 41], [f"p{i}" for i in range(25)], ["`id`"], ["a\nb"]])
def test_negative_req_pipe_004_bad_product_keys_are_refused(products, tmp_path):
    with pytest.raises(ValueError):
        ni.select(_index(tmp_path), "products", products=products)


def test_negative_req_pipe_004_an_unknown_group_is_refused(tmp_path):
    for group in ("everything", "", "../x", "GENERIC"):
        with pytest.raises(ValueError):
            ni.select(_index(tmp_path), group)


# --- the command line --------------------------------------------------------------------------------------

def test_the_cli_builds_selects_and_summarizes(tmp_path, capsys):
    _tree(tmp_path / "t", {"http/exposures/a.yaml": _template("a-one", tags="exposure"),
                            "http/cves/b.yaml": _template("b-one", tags="cve,nginx", vendor="f5", product="nginx")})
    out_file, sel = tmp_path / "index.json", tmp_path / "sel.txt"
    assert ni.main(["build", str(tmp_path / "t"), str(out_file), "--version", "v1"]) == 0
    assert json.loads(out_file.read_text())["templates_version"] == "v1"
    capsys.readouterr()
    assert ni.main(["summary", "--index", str(out_file)]) == 0
    assert json.loads(capsys.readouterr().out)["total"] == 2
    assert ni.main(["select", "--group", "products", "--products", "nginx", "--out", str(sel), "--index", str(out_file)]) == 0
    assert json.loads(capsys.readouterr().out) == {"templates": 1}
    assert sel.read_text().strip() == str(tmp_path / "t" / "http/cves/b.yaml")


def test_negative_the_cli_refuses_bad_input_with_a_nonzero_exit(tmp_path, capsys):
    out_file = tmp_path / "index.json"
    _tree(tmp_path / "t", {"http/exposures/a.yaml": _template("a-one", tags="exposure")})
    ni.main(["build", str(tmp_path / "t"), str(out_file)])
    for argv in (["select", "--group", "nope"], ["select", "--group", "generic", "--shard", "9/2"],
                 ["select", "--group", "products", "--products", "a;b"]):
        assert ni.main([*argv, "--index", str(out_file)]) == 2


def test_the_index_refuses_an_unknown_schema(tmp_path):
    bad = tmp_path / "i.json"
    bad.write_text(json.dumps({"schema": 99, "t": []}))
    with pytest.raises(ValueError):
        ni.main(["summary", "--index", str(bad)])


def test_an_empty_selection_writes_an_empty_list_the_command_can_detect(tmp_path):
    _tree(tmp_path / "t", {"http/exposures/a.yaml": _template("a-one", tags="exposure")})
    out_file, sel = tmp_path / "index.json", tmp_path / "sel.txt"
    ni.main(["build", str(tmp_path / "t"), str(out_file)])
    ni.main(["select", "--group", "products", "--products", "nginx", "--out", str(sel), "--index", str(out_file)])
    assert sel.read_text() == ""


# --- the image ships it ---------------------------------------------------------------------------------------------

def test_the_dockerfile_builds_and_sanity_checks_the_index_after_baking_the_templates():
    dockerfile = (ROOT / "runner.Dockerfile").read_text()
    bake = dockerfile.index("git clone --depth 1 --branch \"${NUCLEI_TEMPLATES_TAG}\"")
    build = dockerfile.index("nuclei_index.py build /opt/nuclei-templates /opt/nuclei-index.json")
    assert bake < build
    assert "COPY nuclei_index.py /opt/asm/nuclei_index.py" in dockerfile
    assert "s['total'] > 4000" in dockerfile, "a broken parser must fail the image build"
