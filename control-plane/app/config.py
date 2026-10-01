from functools import lru_cache

from cryptography.fernet import Fernet
from pydantic import model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

# Public development defaults for the object store (REQ-INSTALL-002):
# docker-compose.yml falls back to the first pair, `minioadmin` is what v0.3.0
# and earlier shipped. Production rejects every one of them, and an empty value.
DEV_S3_ACCESS_KEY = "asm-dev-access"
DEV_S3_SECRET_KEY = "asm-dev-secret-change-me"
_PUBLIC_S3_ACCESS_KEYS = {"", "minioadmin", DEV_S3_ACCESS_KEY}
_PUBLIC_S3_SECRET_KEYS = {"", "minioadmin", DEV_S3_SECRET_KEY}


class Settings(BaseSettings):
    # protected_namespaces=(): pydantic's default "model_"/"settings_" guard
    # is meant to catch accidental shadowing of BaseSettings internals, but
    # this class legitimately has settings_encryption_key(_previous) fields
    # (GitHub issue #25) - without this, pydantic emits a spurious warning
    # on every import.
    model_config = SettingsConfigDict(env_file=".env", extra="ignore", protected_namespaces=())

    environment: str = "development"
    operator_api_token: str = "change-me-in-dev"

    # REQ-AGENT-027: the publicly-reachable base URL for THIS deployment,
    # used to build OpenWire callback URLs a probed target must fetch to
    # prove deserialization RCE. Must be reachable from wherever a real
    # target's network can reach - i.e. the actual public domain in int/prod
    # (scan.example.org / scan-int.example.org), not an internal
    # container hostname. The dev default only works for the benchmark VM,
    # which is on the same host.
    public_base_url: str = "http://localhost:8000"

    database_url: str = "postgresql+psycopg://asm:asm@localhost:5432/asm"
    redis_url: str = "redis://localhost:6379/0"

    # Origins a browser console may call this API from, comma-separated. The default
    # is the development console (Vite on port 5173). Production serves the console
    # and the API from one origin and needs none. The manual's screenshot generator
    # (REQ-MANUAL-004) runs its throwaway console on another port and sets this.
    cors_allowed_origins: str = "http://localhost:5173"

    # GitHub issue #31 (REQ-IAM-016): attempts per source IP on the
    # unauthenticated login steps, per window. Looser than the per-account
    # lockout, so several users behind one address can still sign in.
    # 0 disables the limit.
    login_rate_limit_attempts: int = 30
    login_rate_limit_window_seconds: int = 300
    # REQ-IAM-017: only these peers may tell us the client's address via
    # X-Forwarded-For (the edge reaches the control plane from a private
    # Docker network or the host). Anyone else's header is ignored.
    trusted_proxy_cidrs: str = "127.0.0.0/8,::1/128,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,fc00::/7"

    # REQ-IAM-019: origins (besides the host a request was sent to) whose
    # cookie-authenticated state-changing requests are accepted - the dev console.
    csrf_trusted_origins: str = "http://localhost:5173"

    # S3-compatible object store (SeaweedFS, REQ-INSTALL-002). The defaults are
    # public development values; production rejects them (see the validator).
    s3_endpoint: str = "http://localhost:8333"
    s3_access_key: str = DEV_S3_ACCESS_KEY
    s3_secret_key: str = DEV_S3_SECRET_KEY
    s3_bucket: str = "asm-evidence"

    # Vector Agent (Phase 4) and Lens Agent: OpenAI-kompatibler LLM-Provider (z. B. OpenAI, Eden
    # AI, ein lokaler Gateway). base_url/api_key/model sind die Env-DEFAULTS;
    # zur Laufzeit ueberschreibt eine app_setting-Zeile ('llm_config', via GUI)
    # diese Werte (s. app/settings_store.py). anthropic_api_key bleibt fuer
    # Rueckwaertskompatibilitaet, wird aber vom Agenten nicht mehr genutzt.
    anthropic_api_key: str = ""
    llm_base_url: str = ""            # z. B. https://api.openai.com/v1 oder Eden-AI-Endpoint
    llm_api_key: str = ""
    llm_model: str = ""               # provider-spezifischer Modellname

    # Optional (REQ-CORR-008): erhoeht NVDs Rate-Limit von 5/30s auf 50/30s.
    # Fehlt er, arbeitet die Korrelation korrekt (nur langsamer) ohne Key.
    nvd_api_key: str = ""

    # Signiert intern erzeugte Approval-/Report-Referenzen; ersetzt Vault/SOPS
    # im lokalen M1-Skeleton (siehe Deployment-Architektur Kap. 7.2).
    scope_signing_secret: str = "change-me-in-dev"
    # Separate capability key for short-lived raw-egress leases. The gateway
    # receives only this verifier key, never the operator/internal API token.
    raw_egress_signing_secret: str = "raw-egress-change-me-in-dev"
    raw_egress_lease_ttl_seconds: int = 900
    raw_egress_materialization_max_age_seconds: int = 900
    nmap_max_rate: int = 300
    # GitHub issue #35: no upper bound previously existed anywhere - a `cidr`
    # scope asset of any size (including 0.0.0.0/0) could be registered and,
    # if active_allowed, swept with no operator-visible warning. 65536 (a
    # /16 for IPv4) is a conservative, order-of-magnitude-only default: at
    # nmap_max_rate's own default (300 pps, 2 discovery ports/host - REQ-
    # CIDRDISC-002), that many addresses take ~7 minutes; the platform's own
    # realistic bug-bounty/ASM engagements are expected to scope far smaller
    # ranges than this. Not informed by a full packet-budget model (that is
    # GitHub issue #37's scope) - deliberately simple and revisable.
    max_host_discovery_addresses: int = 65536
    # Ein Lauf ohne heartbeat_at-Update fuer laenger als dies gilt als
    # verwaist und wird geerntet (REQ-RAWLEASE-001). Groesser als das
    # Worker-Heartbeat-Intervall, kleiner als die Nutzlebensdauer eines Laufs.
    stale_run_seconds: int = 300
    # GitHub issue #42 (REQ-RESUME-003): how often the reaper resumes a claimed
    # run whose worker died before giving up and aborting it.
    scan_max_resumes: int = 2
    # Shared secret for /internal/* routes. Dev default is intentionally only
    # a local placeholder; production must inject this via Vault/SOPS.
    internal_api_token: str = "change-me-in-dev"
    # GitHub issue #17: control-plane does not itself call the tool-runner -
    # this field exists purely so the ONE component with an enforced
    # production settings validator also catches a runner token left at its
    # dev default, rather than that failure mode being reachable only via
    # tool-runner's own separate startup guard (runner_auth.py), which a
    # deployment topology gap (ENVIRONMENT never reaching that container) had
    # silently defeated.
    runner_api_token: str = "runner-change-me-in-dev"
    # GitHub issue #22: same reasoning as runner_api_token above - control-
    # plane never calls the raw-egress gateway's reservation/lease API
    # itself, but reads this purely so its own enforced production
    # validator catches it left at the dev default too.
    raw_egress_api_token: str = "raw-egress-api-change-me-in-dev"

    default_max_rps: float = 5.0

    # GitHub issue #49 (REQ-PIPE-019): the database pool, sized on purpose. The
    # SQLAlchemy defaults (5 + 10, 30 s checkout) were shorter than the demand of a
    # scan with the console open and far longer than the worker's 2 s cancel-check
    # timeout, so a stall looked like a dead control plane.
    db_pool_size: int = 10
    db_max_overflow: int = 10
    db_pool_timeout_seconds: float = 10.0
    # The egress proxy's audit and rate-reservation calls (100+ per second in a
    # scan) may hold at most this many database connections at once, so cancel
    # checks, heartbeats and the console always find a free one. A caller that
    # cannot get a slot within internal_bulk_wait_seconds gets 503 and the proxy
    # fails closed (REQ-EGRESS-003).
    internal_bulk_db_slots: int = 4
    internal_bulk_wait_seconds: float = 3.0

    # REQ-IAM-004: encrypts TOTP secrets at rest (Fernet key, urlsafe-base64
    # 32 bytes). Separate from the DB credential on purpose - a compromised
    # DB dump alone must not yield usable MFA secrets. No key ships in source:
    # provide MFA_ENCRYPTION_KEY via the environment (`make env` generates one
    # into .env for local use). Empty is rejected in production (see the guard
    # below); in dev MFA answers 503 until it is set (REQ-INSTALL-004).
    mfa_encryption_key: str = ""

    # GitHub issue #25: encrypts LLM/NVD provider API keys at rest in
    # app_setting JSONB (mirrors mfa_encryption_key's pattern, but with a
    # DISTINCT key - a leak of one must not expose the other). Optional
    # comma-separated *_previous list supports key rotation: the primary key
    # always encrypts; any previous key can still decrypt values written
    # before a rotation (write-new/read-old).
    settings_encryption_key: str = ""
    settings_encryption_key_previous: str = ""


    def cors_origin_list(self) -> list[str]:
        return [origin.strip() for origin in self.cors_allowed_origins.split(",") if origin.strip()]

    @model_validator(mode="after")
    def reject_insecure_production_defaults(self):
        if self.environment.lower() != "production":
            return self
        insecure = []
        if self.operator_api_token in ("", "change-me-in-dev"):
            insecure.append("operator_api_token")
        if self.internal_api_token in ("", "change-me-in-dev"):
            insecure.append("internal_api_token")
        if self.runner_api_token in ("", "runner-change-me-in-dev"):
            insecure.append("runner_api_token")
        if self.raw_egress_api_token in ("", "raw-egress-api-change-me-in-dev"):
            insecure.append("raw_egress_api_token")
        if self.scope_signing_secret in ("", "change-me-in-dev"):
            insecure.append("scope_signing_secret")
        if self.raw_egress_signing_secret in ("", "raw-egress-change-me-in-dev"):
            insecure.append("raw_egress_signing_secret")
        if self.mfa_encryption_key == "":
            insecure.append("mfa_encryption_key")
        # GitHub issue #25: unlike the other dev-default checks above, an
        # empty OR malformed key is caught here, not just the literal dev
        # placeholder - "startup with a missing/incorrect encryption key
        # fails loudly" was an explicit acceptance criterion, and a key that
        # merely LOOKS set but cannot construct a Fernet cipher would
        # otherwise only surface much later, as a confusing 500 the first
        # time an operator actually saves or reads a provider API key.
        if self.settings_encryption_key == "":
            insecure.append("settings_encryption_key")
        else:
            try:
                Fernet(self.settings_encryption_key.encode())
            except ValueError:
                insecure.append("settings_encryption_key")
        if not 60 <= self.raw_egress_lease_ttl_seconds <= 1800:
            insecure.append("raw_egress_lease_ttl_seconds")
        if not 1 <= self.nmap_max_rate <= 1000:
            insecure.append("nmap_max_rate")
        if not (1 <= self.db_pool_size <= 100 and 0 <= self.db_max_overflow <= 100
                and 1 <= self.db_pool_timeout_seconds <= 60):
            insecure.append("db_pool")
        if not 1 <= self.internal_bulk_db_slots < self.db_pool_size + self.db_max_overflow:
            insecure.append("internal_bulk_db_slots")
        if "asm:asm@" in self.database_url or "localhost" in self.database_url:
            insecure.append("database_url")
        # REQ-INSTALL-002: both the current development default and the one
        # v0.3.0 and earlier shipped (`minioadmin`) are public; an empty value
        # would also leave the store without a credential.
        if (
            self.s3_access_key in _PUBLIC_S3_ACCESS_KEYS
            or self.s3_secret_key in _PUBLIC_S3_SECRET_KEYS
        ):
            insecure.append("s3_credentials")
        # GitHub issue #21: an unreachable-from-outside public_base_url (the
        # dev default, or any http:// / localhost / 127.0.0.1 value) makes
        # REQ-AGENT-027's OpenWire callback URLs unusable in production - the
        # generated URL tells the TARGET to call itself, so CVE-2023-46604
        # confirmation silently never succeeds.
        if (
            not self.public_base_url
            or self.public_base_url.startswith("http://")
            or "localhost" in self.public_base_url
            or "127.0.0.1" in self.public_base_url
        ):
            insecure.append("public_base_url")
        if insecure:
            raise ValueError("insecure production configuration: " + ", ".join(insecure))
        return self


@lru_cache
def get_settings() -> Settings:
    return Settings()
