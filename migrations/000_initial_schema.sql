-- 000_initial_schema.sql
CREATE TABLE
    scans (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid (),
        started_at TIMESTAMPTZ NOT NULL DEFAULT NOW (),
        finished_at TIMESTAMPTZ,
        status TEXT NOT NULL DEFAULT 'running' -- 'running', 'complete', 'failed'
    );

CREATE TABLE
    cpes (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid (),
        name TEXT NOT NULL,
        product TEXT NOT NULL,
        vendor TEXT,
        version TEXT,
        source TEXT NOT NULL,
        cpe TEXT, -- computed CPE string, nullable until resolved
        cpe_confidence TEXT NOT NULL DEFAULT 'low',
        first_seen TIMESTAMPTZ NOT NULL DEFAULT NOW (),
        last_seen TIMESTAMPTZ NOT NULL DEFAULT NOW (),
        UNIQUE (name, product)
    );

CREATE TABLE
    cves (
        cve_id TEXT PRIMARY KEY,
        description TEXT,
        refs JSONB,
        cvss_score NUMERIC(4, 2),
        cvss_vector TEXT,
        cvss_version TEXT,
        published_at TIMESTAMPTZ,
        first_seen TIMESTAMPTZ NOT NULL DEFAULT NOW (),
        last_seen TIMESTAMPTZ NOT NULL DEFAULT NOW ()
    );

CREATE TABLE
    cve_symbols (
        id BIGSERIAL PRIMARY KEY,
        cve_id TEXT NOT NULL REFERENCES cves (cve_id) ON DELETE CASCADE,
        name TEXT NOT NULL,
        source TEXT NOT NULL,
        confidence TEXT NOT NULL,
        symbol_type TEXT NOT NULL,
        context TEXT NOT NULL,
        UNIQUE (cve_id, name)
    );

CREATE INDEX ON cve_symbols (cve_id);

CREATE INDEX ON cve_symbols (name);

CREATE TABLE
    symbol_observations (
        id BIGSERIAL PRIMARY KEY,
        cve_symbol_id BIGINT NOT NULL REFERENCES cve_symbols (id) ON DELETE CASCADE,
        pid INT,
        process_name TEXT,
        observed_at TIMESTAMPTZ NOT NULL DEFAULT NOW (),
        call_count BIGINT NOT NULL DEFAULT 1
    );

CREATE INDEX ON symbol_observations (cve_symbol_id);

CREATE TABLE
    findings (
        id BIGSERIAL PRIMARY KEY,
        scan_id UUID NOT NULL REFERENCES scans (id) ON DELETE CASCADE,
        cpe_id UUID NOT NULL REFERENCES cpes (id) ON DELETE CASCADE,
        cve_id TEXT NOT NULL REFERENCES cves (cve_id) ON DELETE CASCADE,
        cpe_match BOOLEAN NOT NULL DEFAULT false,
        symbol_present BOOLEAN,
        symbol_called BOOLEAN,
        cvss_score NUMERIC(4, 2),
        kev_listed BOOLEAN NOT NULL DEFAULT false,
        rank_score NUMERIC(6, 3),
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW (),
        updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW (),
        UNIQUE (scan_id, cpe_id, cve_id)
    );

CREATE INDEX ON findings (rank_score DESC);

CREATE INDEX ON findings (cve_id);

CREATE TABLE
    kev (
        cve_id TEXT PRIMARY KEY REFERENCES cves (cve_id) ON DELETE CASCADE,
        vendor TEXT,
        product TEXT,
        added_at DATE
    );