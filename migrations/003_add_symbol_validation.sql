ALTER TABLE cve_symbols
    ADD COLUMN binary_path TEXT,
    ADD COLUMN probe_type TEXT,
    ADD COLUMN validated BOOLEAN NOT NULL DEFAULT FALSE;

CREATE INDEX idx_cve_symbols_validated ON cve_symbols (validated) WHERE validated = TRUE;