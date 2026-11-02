"""Keeps the deny-all policy's two allowed endpoints in step with their names (REQ-RAWLEASE-005, REQ-RAWLEASE-006).

The runner's namespace may reach exactly two things besides a leased target: the egress proxy and, when configured, the
interaction server. Both are Compose services, and recreating one gives it a new address. The policy used to learn the
addresses once, at start-up, so after the proxy was recreated the runner could no longer reach it - and every web tool
read the refused connections as "nothing found". This watcher looks the names up again every few seconds, hands changes
to the gateway (which replaces only those two address sets), and checks from inside the runner's namespace that the
proxy accepts a connection, so /health says so.

Two independent loops, because a lookup can be slow: Docker answers a name it does not know (a stopped container) by
asking an upstream resolver, and this namespace's own deny-all policy drops that query, so the lookup takes 5 seconds
to fail (measured on the dev stack). The reachability check therefore never waits for a lookup - it connects to the
addresses directly - and a lookup that does not answer in time is abandoned for that pass.

It decides nothing about scope. It only ever changes the addresses of the two named services, and only to what the
name resolves to now, minus anything that cannot be a service on a bridge network (unspecified, loopback, link-local,
multicast, reserved).
"""

from __future__ import annotations

import ipaddress
import socket
import threading
import time
from typing import Callable

from app.gateway import PolicyError

DEFAULT_INTERVAL_S = 2.0
RECOVERY_INTERVAL_S = 1.0  # while the proxy is unreachable: look again soon, so recovery shows within a second or two
PROBE_TIMEOUT_S = 1.0
LOOKUP_TIMEOUT_S = 1.5
MAX_LOOKUPS_IN_FLIGHT = 8


def vet(addresses) -> list[str]:
    """Sorted, unique, usable service addresses out of whatever a lookup returned."""
    found: set[str] = set()
    for value in addresses:
        try:
            ip = ipaddress.ip_address(str(value).split("%", 1)[0])
        except ValueError:
            continue
        if ip.is_unspecified or ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_reserved:
            continue
        found.add(str(ip))
    return sorted(found)


def resolve(host: str, port: int, family: int = 0) -> list[str]:
    """What `host` resolves to now (vetted); an empty list when it does not resolve."""
    try:
        infos = socket.getaddrinfo(host, port, family, socket.SOCK_STREAM, socket.IPPROTO_TCP)
    except OSError:
        return []
    return vet(item[4][0] for item in infos)


def probe_tcp(addresses: list[str], port: int) -> bool:
    """Whether a TCP connection to any of these addresses is accepted from this namespace (its firewall applies)."""
    for address in addresses:
        try:
            with socket.create_connection((address, port), timeout=PROBE_TIMEOUT_S):
                return True
        except OSError:
            continue
    return False


class EndpointWatcher:
    def __init__(
        self, gateway, *, proxy_host: str, proxy_port: int, oob_host: str = "", oob_port: int = 8080,
        interval: float = DEFAULT_INTERVAL_S, resolver: Callable[[str, int, int], list[str]] = resolve,
        prober: Callable[[list[str], int], bool] = probe_tcp, clock: Callable[[], float] = time.time,
        log: Callable[[str], None] = lambda message: print(message, flush=True),
        lookup_timeout: float = LOOKUP_TIMEOUT_S,
    ):
        self._gateway = gateway
        self._proxy = (proxy_host, int(proxy_port))
        self._oob = (oob_host, int(oob_port)) if oob_host else None
        self._interval = max(0.01, float(interval))
        self._resolver, self._prober, self._clock, self._log = resolver, prober, clock, log
        self._lookup_timeout = lookup_timeout
        self._lock = threading.Lock()
        self._lookups = threading.BoundedSemaphore(MAX_LOOKUPS_IN_FLIGHT)
        self._latest_proxy: list[str] | None = None  # the last non-empty answer for the proxy's name
        self._state = {
            "proxy_resolved": None, "proxy_reachable": None, "oob_resolved": None,
            "checked_at": None, "changed_at": None, "refresh_error": None,
        }
        self._stop = threading.Event()

    # --- one pass of each loop (also what the tests drive) ---

    def check(self) -> None:
        """One pass of every loop. Never raises."""
        self.check_resolution()
        self.check_oob()
        self.check_reachability()

    def check_resolution(self) -> None:
        """The proxy's name: look it up, hand a moved address to the policy."""
        try:
            self._resolution()
        except Exception as exc:  # noqa: BLE001 - a watcher that dies would silently stop following the proxy
            self._note(refresh_error=f"unexpected:{type(exc).__name__}")

    def check_oob(self) -> None:
        """The interaction server's name, on its own so that a name that never resolves (no server on this stack) cannot
        slow the proxy's loop down."""
        if self._oob is None:
            return
        try:
            self._oob_resolution()
        except Exception as exc:  # noqa: BLE001
            self._note(refresh_error=f"unexpected:{type(exc).__name__}")

    def check_reachability(self) -> None:
        try:
            self._reachability()
        except Exception:  # noqa: BLE001
            self._note(proxy_reachable=None)

    def _lookup(self, host: str, port: int, family: int) -> list[str]:
        """The vetted answer, or [] when there is none or it did not come in time (that lookup is abandoned: its
        thread ends by itself and its answer is dropped). Bounded, so a resolver that hangs cannot pile up threads."""
        if not self._lookups.acquire(blocking=False):
            return []
        box: dict[str, list[str]] = {}

        def work() -> None:
            try:
                box["found"] = self._resolver(host, port, family)
            except Exception:  # noqa: BLE001 - reported below as "no answer"; the pass must not die with it
                pass
            finally:
                self._lookups.release()

        thread = threading.Thread(target=work, name="endpoint-lookup", daemon=True)
        thread.start()
        thread.join(self._lookup_timeout)
        return list(box.get("found", []))

    def _refresh(self, *, proxy: list[str] | None = None, oob: list[str] | None = None) -> tuple[bool, str | None]:
        """Hand what was found to the policy; (changed, error). An empty lookup is not "the endpoint is gone": it is
        passed on as None, so the last known addresses stay and /health says the name did not resolve."""
        try:
            return bool(self._gateway.refresh_endpoints(proxy_addresses=proxy or None, oob_addresses=oob or None)), None
        except PolicyError as exc:
            return False, str(exc)[:200]

    def _report(self, changed: bool, error: str | None) -> None:
        with self._lock:
            before_error = self._state["refresh_error"]
        if changed:
            self._log("raw-egress-gateway: the proxy / interaction-server address changed; policy updated")
        if error and error != before_error:
            self._log(f"raw-egress-gateway: could not update the policy for a moved address: {error}")

    def _resolution(self) -> None:
        proxy_found = self._lookup(self._proxy[0], self._proxy[1], 0)
        changed, error = self._refresh(proxy=proxy_found)
        self._report(changed, error)
        with self._lock:
            if proxy_found:
                self._latest_proxy = list(proxy_found)
        self._note(proxy_resolved=bool(proxy_found), refresh_error=error, **({"changed_at": self._clock()} if changed else {}))

    def _oob_resolution(self) -> None:
        oob_found = self._lookup(self._oob[0], self._oob[1], socket.AF_INET)
        changed, error = self._refresh(oob=oob_found)
        self._report(changed, error)
        self._note(oob_resolved=bool(oob_found), **({"refresh_error": error} if error else {}), **({"changed_at": self._clock()} if changed else {}))

    def _reachability(self) -> None:
        installed = list(self._gateway.proxy_addresses())
        with self._lock:
            latest = None if self._latest_proxy is None else list(self._latest_proxy)
            before = self._state["proxy_reachable"]
        # What the runner would do: it resolves the name and connects to the answer. So only an address that the name
        # resolves to AND the policy lets through counts; while the policy lags behind a moved proxy, that is nothing.
        targets = installed if latest is None else [address for address in installed if address in latest]
        reachable = bool(targets) and bool(self._prober(targets, self._proxy[1]))
        if before is not None and reachable != before:
            self._log(f"raw-egress-gateway: the runner {'can' if reachable else 'can NOT'} reach the egress proxy")
        self._note(proxy_reachable=reachable, checked_at=self._clock())

    def _note(self, **values) -> None:
        with self._lock:
            self._state.update(values)

    def status(self) -> dict:
        """What /health shows: booleans and times only (the endpoint is unauthenticated; no addresses)."""
        with self._lock:
            s = dict(self._state)
        return {
            "proxy": {
                "resolved": s["proxy_resolved"], "reachable": s["proxy_reachable"],
                "checked_at": s["checked_at"], "changed_at": s["changed_at"], "refresh_error": s["refresh_error"],
            },
            "oob": {"configured": self._oob is not None, "resolved": s["oob_resolved"]},
        }

    # --- the loops ---

    def _loop(self, check: Callable[[], None]) -> None:
        while not self._stop.is_set():
            check()
            self._stop.wait(self._interval)

    def _reachability_loop(self) -> None:
        while not self._stop.is_set():
            self.check_reachability()
            down = self.status()["proxy"]["reachable"] is False
            self._stop.wait(min(self._interval, RECOVERY_INTERVAL_S) if down else self._interval)

    def start(self) -> list[threading.Thread]:
        threads = [
            threading.Thread(target=self._loop, args=(self.check_resolution,), name="endpoint-resolution", daemon=True),
            threading.Thread(target=self._reachability_loop, name="endpoint-reachability", daemon=True),
        ]
        if self._oob is not None:
            threads.append(threading.Thread(target=self._loop, args=(self.check_oob,), name="endpoint-oob", daemon=True))
        for thread in threads:
            thread.start()
        return threads

    def stop(self) -> None:
        self._stop.set()
