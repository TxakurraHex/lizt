CREATE OR REPLACE FUNCTION compute_rank_score(
       cvss     NUMERIC,
       kev      BOOLEAN,
       called   BOOLEAN
) RETURNS NUMERIC AS $$
       SELECT
           COALESCE(cvss, 0)
       * CASE WHEN called   THEN 2.0 ELSE 1.0 END
       + CASE WHEN kev      THEN 3.0 ELSE 0.0 END
$$ LANGUAGE sql IMMUTABLE;