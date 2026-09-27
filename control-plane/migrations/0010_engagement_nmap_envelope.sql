-- REQ-SCAN-011/013: persisted TCP envelope and explicit bounded UDP opt-in.
ALTER TABLE engagement
    ADD COLUMN tcp_port_from INTEGER NOT NULL DEFAULT 1,
    ADD COLUMN tcp_port_to INTEGER NOT NULL DEFAULT 65535,
    ADD COLUMN udp_discovery_enabled BOOLEAN NOT NULL DEFAULT false,
    ADD CONSTRAINT ck_engagement_tcp_port_from CHECK (tcp_port_from BETWEEN 1 AND 65535),
    ADD CONSTRAINT ck_engagement_tcp_port_to CHECK (tcp_port_to BETWEEN 1 AND 65535),
    ADD CONSTRAINT ck_engagement_tcp_port_order CHECK (tcp_port_from <= tcp_port_to);
