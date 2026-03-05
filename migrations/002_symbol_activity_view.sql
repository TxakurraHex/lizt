CREATE MATERIALIZED VIEW symbol_activity AS
       SELECT
           cve_symbol_id,
           COUNT(*)             AS total_calls,
           MAX(observed_at)     AS last_seen,
           COUNT(DISTINCT pid)  AS distinct_pids
       FROM symbol_observations
       GROUP BY cve_symbol_id;

CREATE UNIQUE INDEX ON symbol_activity(cve_symbol_id);