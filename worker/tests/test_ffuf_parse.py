import json

from app.ffuf_parse import parse_ffuf_json


def test_parses_hits():
    payload = {
        "results": [
            {"input": {"FUZZ": "admin"}, "url": "https://h/admin", "status": 200, "length": 512},
            {"input": {"FUZZ": ".git/config"}, "url": "https://h/.git/config", "status": 200, "length": 92},
            {"input": {"FUZZ": "login"}, "url": "https://h/login", "status": 401, "length": 0},
        ]
    }
    hits = parse_ffuf_json(json.dumps(payload))
    assert len(hits) == 3
    assert hits[0]["word"] == "admin" and hits[0]["status"] == 200 and hits[0]["length"] == 512
    assert hits[1]["word"] == ".git/config"


def test_empty_and_garbage():
    assert parse_ffuf_json("") == []
    assert parse_ffuf_json("not json") == []
    assert parse_ffuf_json(json.dumps({"results": []})) == []
