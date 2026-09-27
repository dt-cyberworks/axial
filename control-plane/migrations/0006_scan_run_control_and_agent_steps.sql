-- Scan-Run-Steuerung (kooperativer Stopp) + Agent-Transparenz (Prompt/Antwort
-- je Iteration).
--
-- 1) scan_run bekommt ein kooperatives Stopp-Flag: der Operator setzt es, der
--    Worker prueft es an Phasengrenzen + in der Agent-Schleife und beendet
--    sauber (state='aborted', state_reason='cancelled_by_operator').
-- 2) agent_step haelt pro Vector-Agent-Iteration den an das Modell gesendeten
--    Kontext und dessen Antwort fest - Grundlage des GUI-Drilldowns. Der
--    api_key wird NIE gespeichert (der Worker sendet nur die Nachrichten).

ALTER TABLE scan_run
  ADD COLUMN IF NOT EXISTS cancel_requested BOOLEAN NOT NULL DEFAULT false;
ALTER TABLE scan_run
  ADD COLUMN IF NOT EXISTS state_reason TEXT;

CREATE TABLE IF NOT EXISTS agent_step (
  id                  UUID PRIMARY KEY DEFAULT uuidv7(),
  engagement_id       UUID NOT NULL REFERENCES engagement(id),
  scan_run_id         UUID NOT NULL REFERENCES scan_run(id),
  iteration           INT NOT NULL,
  request_messages    JSONB NOT NULL,   -- system + laufende Nachrichtenliste (ohne Secrets)
  response_text       TEXT,             -- Klartext-Antwort des Modells
  response_tool_calls JSONB,            -- vom Modell vorgeschlagene Tool-Calls
  stop_reason         TEXT,             -- OpenAI finish_reason / tool_calls / error
  created_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_agent_step_run ON agent_step(scan_run_id, iteration);
CREATE INDEX IF NOT EXISTS idx_agent_step_engagement ON agent_step(engagement_id);
