ALTER TABLE symbol_observations ADD CONSTRAINT symbol_observations_cve_symbol_pid_unique UNIQUE (cve_symbol_id, pid);

DROP MATERIALIZED VIEW symbol_activity;

CREATE MATERIALIZED VIEW symbol_activity AS
SELECT
    cve_symbol_id,
    SUM(call_count) AS total_calls,
    MAX(observed_at) AS last_seen,
    COUNT(DISTINCT pid) AS distinct_pids
FROM
    symbol_observations
GROUP BY
    cve_symbol_id;

CREATE UNIQUE INDEX ON symbol_activity (cve_symbol_id);