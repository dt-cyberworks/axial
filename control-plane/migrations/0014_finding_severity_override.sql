-- REQ-FIDELITY-004: rescore_open_findings previously overwrote EVERY open
-- finding's severity with a freshly computed value on every scan, discarding
-- any tool- or agent-assessed severity_override (e.g. a critical PII exposure
-- silently downgraded to 'low' on the next rescore). Persist the override
-- (mirrors the existing is_kev persistence pattern) so rescoring can respect it.

ALTER TABLE finding
  ADD COLUMN IF NOT EXISTS severity_override TEXT;
