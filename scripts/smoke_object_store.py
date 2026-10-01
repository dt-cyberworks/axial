#!/usr/bin/env python3
"""Prove the object store behaves as REQ-INSTALL-002 says, from inside the stack.

Run it with the control-plane's own environment (so it uses the credentials the
stack really has), through stdin so the file need not be in the image:

    docker compose exec -T control-plane python - control-plane < scripts/smoke_object_store.py
    docker compose exec -T worker        python - worker        < scripts/smoke_object_store.py

Role `control-plane` (the only service on the object-store network):
  * S3 answers, and REQUIRES credentials: an anonymous request and a request with a
    wrong secret are both 403; the configured credentials can create a bucket and
    write, read, list and delete an object (AWS Signature V4, standard library only);
  * the unauthenticated master / volume / filer / Iceberg / Lance interfaces are not
    reachable from the network - they are bound to the container's loopback or off.
Role `worker` (or any other service): the object store cannot even be resolved.

Exit 0 when every check passes, 1 otherwise. Never prints a credential.
"""

from __future__ import annotations

import datetime as dt
import hashlib
import hmac
import os
import socket
import sys
import urllib.error
import urllib.parse
import urllib.request

HOST = "seaweedfs"
S3_PORT = 8333
# Unauthenticated interfaces SeaweedFS can start; none may answer on the network.
CLOSED_PORTS = {8888: "filer", 9333: "master", 8080: "volume server", 8181: "Iceberg catalog", 9101: "Lance namespace"}
failures = 0


def check(label: str, ok: bool, detail: str = "") -> None:
    global failures
    print(f"{'PASS' if ok else 'FAIL'}  {label} {detail}".rstrip(), flush=True)
    failures += 0 if ok else 1


def _hmac(key: bytes, message: str) -> bytes:
    return hmac.new(key, message.encode(), hashlib.sha256).digest()


def s3(method: str, path: str, *, body: bytes = b"", query: str = "", access: str | None = None, secret: str | None = None) -> tuple[int, bytes]:
    """One S3 request, signed with AWS Signature V4 when credentials are given."""
    endpoint = os.environ.get("S3_ENDPOINT", f"http://{HOST}:{S3_PORT}")
    host = urllib.parse.urlsplit(endpoint).netloc
    headers = {}
    if access and secret:
        now = dt.datetime.now(dt.timezone.utc)
        amz_date, date = now.strftime("%Y%m%dT%H%M%SZ"), now.strftime("%Y%m%d")
        payload_hash = hashlib.sha256(body).hexdigest()
        signed = {"host": host, "x-amz-content-sha256": payload_hash, "x-amz-date": amz_date}
        signed_names = ";".join(sorted(signed))
        canonical = "\n".join([
            method, urllib.parse.quote(path, safe="/"), query,
            "".join(f"{name}:{signed[name]}\n" for name in sorted(signed)), signed_names, payload_hash,
        ])
        scope = f"{date}/us-east-1/s3/aws4_request"
        to_sign = "\n".join(["AWS4-HMAC-SHA256", amz_date, scope, hashlib.sha256(canonical.encode()).hexdigest()])
        key = _hmac(_hmac(_hmac(_hmac(("AWS4" + secret).encode(), date), "us-east-1"), "s3"), "aws4_request")
        signature = hmac.new(key, to_sign.encode(), hashlib.sha256).hexdigest()
        headers = {
            "x-amz-date": amz_date, "x-amz-content-sha256": payload_hash,
            "Authorization": f"AWS4-HMAC-SHA256 Credential={access}/{scope}, SignedHeaders={signed_names}, Signature={signature}",
        }
    url = endpoint + path + (f"?{query}" if query else "")
    request = urllib.request.Request(url, method=method, data=body if method in ("PUT", "POST") else None, headers=headers)
    try:
        with urllib.request.urlopen(request, timeout=20) as response:
            return response.status, response.read()
    except urllib.error.HTTPError as error:
        return error.code, error.read()


def port_open(port: int) -> bool:
    try:
        with socket.create_connection((HOST, port), timeout=3):
            return True
    except OSError:
        return False


def control_plane_checks() -> None:
    access, secret = os.environ["S3_ACCESS_KEY"], os.environ["S3_SECRET_KEY"]
    bucket = "asm-smoke-" + hashlib.sha256(os.urandom(8)).hexdigest()[:8]
    payload = b"evidence-" + os.urandom(8).hex().encode()

    status, _ = s3("PUT", f"/{bucket}")
    check("S3 refuses an anonymous request", status == 403, f"-> {status}")
    status, _ = s3("PUT", f"/{bucket}", access=access, secret="wrong-" + secret)
    check("S3 refuses a request signed with a wrong secret", status == 403, f"-> {status}")
    status, _ = s3("PUT", f"/{bucket}", access=access, secret=secret)
    check("the configured credentials can create a bucket", status == 200, f"-> {status}")
    status, _ = s3("PUT", f"/{bucket}/run/out.txt", body=payload, access=access, secret=secret)
    check("... write an object", status == 200, f"-> {status}")
    status, data = s3("GET", f"/{bucket}/run/out.txt", access=access, secret=secret)
    check("... read it back identically", status == 200 and data == payload, f"-> {status}")
    status, data = s3("GET", f"/{bucket}", query="list-type=2", access=access, secret=secret)
    check("... list it", status == 200 and b"run/out.txt" in data, f"-> {status}")
    status, _ = s3("GET", f"/{bucket}/run/out.txt")
    check("an anonymous read of the object is refused", status == 403, f"-> {status}")
    status, _ = s3("DELETE", f"/{bucket}/run/out.txt", access=access, secret=secret)
    check("... delete the object", status in (200, 204), f"-> {status}")
    s3("DELETE", f"/{bucket}", access=access, secret=secret)  # tidy up; not an assertion

    check(f"the S3 gateway answers on {HOST}:{S3_PORT}", port_open(S3_PORT))
    for port, name in sorted(CLOSED_PORTS.items()):
        check(f"the unauthenticated {name} interface (:{port}) is NOT reachable from the network", not port_open(port))


def other_service_checks() -> None:
    try:
        socket.gethostbyname(HOST)
        resolvable = True
    except OSError:
        resolvable = False
    check("the object store cannot be resolved from this service (isolated network)", not resolvable)


def main() -> int:
    role = sys.argv[1] if len(sys.argv) > 1 else "control-plane"
    print(f"== object store checks as: {role}")
    control_plane_checks() if role == "control-plane" else other_service_checks()
    print("OBJECT STORE OK" if not failures else f"{failures} CHECK(S) FAILED")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
