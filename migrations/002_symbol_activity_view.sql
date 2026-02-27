CREATE MATERIALIZED VIEW symbol_activity AS
       SELECT
           symbol,
           COUNT(*)             AS total_calls,
           MAX(observed_at)     AS last_seen,
           COUNT(DISTINCT pid)  AS distinct_pids
       FROM symbol_observations
       GROUP BY symbol;

CREATE UNIQUE INDEX ON symbol_activity(symbol);