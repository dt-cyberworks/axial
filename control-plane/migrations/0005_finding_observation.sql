-- Pro-Lauf-Beobachtung von Findings - Grundlage fuer den Scan-Diff (neu/behoben
-- zwischen aufeinanderfolgenden Laeufen).
--
-- Findings selbst sind engagement-weit und werden ueber fingerprint dedupliziert
-- (ein Fund = eine Zeile ueber Laeufe hinweg). Diese Tabelle haelt fest, WELCHE
-- Fingerprints in WELCHEM scan_run beobachtet wurden. Der Diff zweier Laeufe ist
-- dann die Mengendifferenz ihrer beobachteten Fingerprints:
--   neu      = im Lauf beobachtet, im Vorgaenger nicht
--   behoben  = im Vorgaenger beobachtet, im Lauf nicht (mehr) gesehen
--   bestehend= in beiden

CREATE TABLE IF NOT EXISTS finding_observation (
  scan_run_id   UUID NOT NULL REFERENCES scan_run(id),
  engagement_id UUID NOT NULL REFERENCES engagement(id),
  fingerprint   TEXT NOT NULL,
  finding_id    UUID NOT NULL REFERENCES finding(id),
  observed_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (scan_run_id, fingerprint)
);

CREATE INDEX IF NOT EXISTS idx_finding_observation_run ON finding_observation(scan_run_id);
CREATE INDEX IF NOT EXISTS idx_finding_observation_engagement ON finding_observation(engagement_id);
