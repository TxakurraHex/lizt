-- Migration: Initial schema
-- Created: 2026-02-15
CREATE TABLE
    IF NOT EXISTS cves (
        cve_id VARCHAR(20) PRIMARY KEY,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );

CREATE TABLE
    IF NOT EXISTS symbols (
        id BIGSERIAL PRIMARY KEY,
        cve_id VARCHAR(20) NOT NULL,
        symbol_name VARCHAR(255) NOT NULL,
        source VARCHAR(500),
        confidence VARCHAR(20),
        context TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (cve_id) REFERENCES cves (cve_id) ON DELETE CASCADE
    );

CREATE INDEX idx_symbols_cve_id ON symbols (cve_id);

CREATE INDEX idx_symbols_symbol_name ON symbols (symbol_name);

CREATE INDEX idx_symbols_cve_symbol ON symbols (cve_id, symbol_name);