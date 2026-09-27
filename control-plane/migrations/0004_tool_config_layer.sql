-- Durchgaengiges Konfigurationsmodell (global + pro Kampagne).
--
-- Schichten:
--   1. Capability-Registry (Code)      = Sicherheitsboden, nicht editierbar
--   2. app_setting['tool_policy']      = globale Tool-Defaults (enabled/approval)
--   3. app_setting['agent_prompt']     = globale Agent-Anweisung (Default)
--   4. tool_approval_policy.enabled    = Kampagnen-Override je Tool (an/aus)
--   5. engagement.agent_prompt_override= Kampagnen-Override der Agent-Anweisung
--
-- Global (2/3) liegt im generischen app_setting (kein Schema-Change noetig).
-- Diese Migration ergaenzt nur die beiden Kampagnen-Override-Spalten.

-- tool_approval_policy wird von einer reinen Approval-Tabelle zur allgemeinen
-- per-Tool-Kampagnen-Policy erweitert: enabled=NULL erbt die globale Policy,
-- true/false ueberschreibt sie fuer genau diese Kampagne.
ALTER TABLE tool_approval_policy
  ADD COLUMN IF NOT EXISTS enabled BOOLEAN;

-- Optionaler Kampagnen-spezifischer Agent-Prompt. NULL/leer -> globaler
-- Default (app_setting['agent_prompt']) bzw. der eingebaute Prompt im Worker.
ALTER TABLE engagement
  ADD COLUMN IF NOT EXISTS agent_prompt_override TEXT;
