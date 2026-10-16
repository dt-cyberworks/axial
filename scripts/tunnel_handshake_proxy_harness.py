"""Test harness only (never part of an image): serve the egress proxy's real client handler.

Used by scripts/verify_tunnel_handshake.py inside a throwaway container with the proxy's own
`app` directory mounted. The database, scope and audit lookups are replaced by "allow", so the reply
to CONNECT and the relay are exactly the code that ships; nothing else is simulated.
"""

import asyncio
import os

os.environ.setdefault("DATABASE_URL", "postgresql+psycopg://x:x@localhost:5432/x")
os.environ["ASM_ENGAGEMENT_ID"] = "019649b8-0000-7000-8000-000000000001"

from app import proxy  # noqa: E402


async def _allow(engagement_id, host, path, port):
    return True, "allow"


async def _audit_ok(writer, engagement_id, decision, reason, payload):
    return True


proxy.evaluate = _allow
proxy.vet_target_host = lambda host, port: host
proxy.load_engagement = lambda engagement_id: {"id": engagement_id, "source": "own_domain"}
proxy._submit_audit_or_deny = _audit_ok


async def main() -> None:
    server = await asyncio.start_server(proxy.handle_client, "0.0.0.0", 3128)
    await server.serve_forever()


asyncio.run(main())
