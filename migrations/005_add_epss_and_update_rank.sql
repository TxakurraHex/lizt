-- Add EPSS (Exploit Prediction Scoring System) columns to cves table.
ALTER TABLE cves ADD COLUMN IF NOT EXISTS epss_score     NUMERIC(6,5);
ALTER TABLE cves ADD COLUMN IF NOT EXISTS epss_percentile NUMERIC(6,5);

-- Drop the old 3-parameter function before creating the new 5-parameter one.
DROP FUNCTION IF EXISTS compute_rank_score(NUMERIC, BOOLEAN, BOOLEAN);

-- Weighted multiplicative ranking function.
--
--   base      = cvss / 10              (normalise to 0-1)
--   epss_mult = 1 + epss * 2           (1.0 – 3.0)
--   kev_mult  = kev  ? 1.5 : 1.0
--   call_mult = called ? 2.0 : present ? 1.3 : 1.0
--   score     = base * epss_mult * kev_mult * call_mult * 10
--
-- Max possible score: 1.0 * 3.0 * 1.5 * 2.0 * 10 = 90
CREATE OR REPLACE FUNCTION compute_rank_score(
       cvss     NUMERIC,
       epss     NUMERIC,
       kev      BOOLEAN,
       called   BOOLEAN,
       present  BOOLEAN
) RETURNS NUMERIC AS $$
       SELECT
           (COALESCE(cvss, 0) / 10.0)
         * (1.0 + COALESCE(epss, 0) * 2.0)
         * CASE WHEN kev     THEN 1.5 ELSE 1.0 END
         * CASE WHEN called  THEN 2.0
               WHEN present THEN 1.3
               ELSE 1.0 END
         * 10
$$ LANGUAGE sql IMMUTABLE;
