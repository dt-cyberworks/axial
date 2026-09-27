-- REQ-AUTHNAME-001: the attestation was always "authorized to scan", never
-- literal domain ownership - rename the columns to say so. Plain rename,
-- existing values (true/false, method text) are preserved unchanged.

ALTER TABLE scope_asset RENAME COLUMN ownership_verified TO authorization_verified;
ALTER TABLE scope_asset RENAME COLUMN ownership_method TO authorization_method;
