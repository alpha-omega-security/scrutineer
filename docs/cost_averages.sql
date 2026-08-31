-- cost_averages.sql
-- Average recorded cost (USD) and token usage across Scrutineer scans.
--
-- Run: sqlite3 -header -column scrutineer.db < cost_averages.sql
--
-- Uses the cost_usd and *_tokens columns on the scans table as written by
-- the worker from the harness result event. Only completed scans with a
-- recorded cost are counted, so queued, running, failed and cancelled rows
-- don't drag the figures toward zero. Remove the WHERE clauses to average
-- every row in the table instead.
--
-- Note on cost: cost_usd is API list-price equivalent (Claude Code's
-- total_cost_usd, or tokens priced against a list-price table for other
-- backends). On a Max/Pro subscription it is an estimate of what the scan
-- would have cost on the API, not what you were billed.
--
-- Note on tokens: input_tokens is uncached input only; on agentic runs most
-- context arrives via cache_read_tokens, so avg_total_tokens is the better
-- "how much did the model process" figure. Both cost and tokens include any
-- auxiliary passes (e.g. the refusal audit) folded into the same scan row.


-- Average cost per scan
SELECT ROUND(AVG(cost_usd), 2) AS avg_cost_usd
FROM scans
WHERE status = 'done'
  AND cost_usd > 0;


-- Average token usage per scan
SELECT
    ROUND(AVG(input_tokens))       AS avg_input_tokens,
    ROUND(AVG(output_tokens))      AS avg_output_tokens,
    ROUND(AVG(cache_read_tokens))  AS avg_cache_read_tokens,
    ROUND(AVG(cache_write_tokens)) AS avg_cache_write_tokens,
    ROUND(AVG(input_tokens + output_tokens + cache_read_tokens + cache_write_tokens)) AS avg_total_tokens
FROM scans
WHERE status = 'done'
  AND cost_usd > 0;
