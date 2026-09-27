-- REQ-REPORT-001: report.id was created without a DB-side default
-- (migrations/0025_report.sql), unlike every other table's uuid_pk() column
-- - the ORM model already declares server_default=uuidv7() (app.models.
-- common.uuid_pk()), so this was a drift between the model's stated intent
-- and the actual schema. Latent, not live-breaking, because the only
-- current writer (app/report_service.py) always sets id explicitly - fixed
-- here so the schema matches every other table's convention and so any
-- future writer that omits id behaves like the rest of the codebase.
ALTER TABLE report ALTER COLUMN id SET DEFAULT uuidv7();
