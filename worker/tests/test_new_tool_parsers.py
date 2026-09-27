from app.httpx_parse import parse_httpx_json
from app.nuclei_parse import parse_nuclei_jsonl
from app.testssl_parse import parse_testssl_json


# --- nuclei ---------------------------------------------------------------
NUCLEI_JSONL = (
    '{"template-id":"tls-version","info":{"name":"TLS Version","severity":"info","tags":["ssl"]},'
    '"matched-at":"example.org:443","host":"example.org"}\n'
    '{"template-id":"CVE-2021-1234","info":{"name":"Example RCE","severity":"critical",'
    '"tags":["cve"],"classification":{"cve-id":["CVE-2021-1234"],"cvss-score":9.8}},'
    '"matched-at":"https://example.org/x","host":"example.org"}\n'
    'not-json-noise\n'
)


def test_nuclei_parses_jsonl_and_maps_cve():
    fs = parse_nuclei_jsonl(NUCLEI_JSONL)
    assert len(fs) == 2
    cve = next(f for f in fs if f["template_id"] == "CVE-2021-1234")
    assert cve["category"] == "cve"
    assert cve["cve_ids"] == ["CVE-2021-1234"]
    assert cve["cvss_base"] == 9.8
    assert cve["severity"] == "critical"
    info = next(f for f in fs if f["template_id"] == "tls-version")
    assert info["category"] == "exposure" and info["cve_ids"] is None


def test_nuclei_empty():
    assert parse_nuclei_jsonl("") == []


# --- httpx ----------------------------------------------------------------
HTTPX_JSON = (
    '{"input":"example.org","url":"https://example.org","port":443,"status_code":200,'
    '"title":"Home","webserver":"nginx","tech":["Nginx","PHP"]}\n'
    '{"input":"dead.example.org"}\n'  # kein status_code -> kein lebender Dienst
)


def test_httpx_extracts_live_hosts_only():
    rows = parse_httpx_json(HTTPX_JSON)
    assert len(rows) == 1
    assert rows[0]["webserver"] == "nginx"
    assert rows[0]["status_code"] == 200
    assert "Nginx" in rows[0]["tech"]


# --- testssl --------------------------------------------------------------
TESTSSL_JSON = (
    '[{"id":"SSLv3","severity":"OK","finding":"not offered"},'
    '{"id":"TLS1","severity":"LOW","finding":"offered (deprecated)"},'
    '{"id":"cert_expirationStatus","severity":"HIGH","finding":"expired"},'
    '{"id":"scanTime","severity":"INFO","finding":"42"}]'
)


def test_testssl_keeps_noteworthy_only():
    fs = parse_testssl_json(TESTSSL_JSON)
    sevs = {f["id"]: f["severity"] for f in fs}
    assert sevs == {"TLS1": "low", "cert_expirationStatus": "high"}  # OK/INFO ausgefiltert


def test_testssl_empty():
    assert parse_testssl_json("") == []
