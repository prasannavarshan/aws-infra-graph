// One-time cleanup: remove duplicate Account nodes (keep the one with earliest last_crawled)
// Run this BEFORE adding the uniqueness constraint if dupes exist with same ARN,
// or after if dupes have different ARNs for the same account_id.

// Step 1: Find accounts with duplicate nodes (same account_id, different ARN)
MATCH (a:Account)
WITH a.account_id AS acct_id, collect(a) AS nodes
WHERE size(nodes) > 1
UNWIND nodes[1..] AS dup
DETACH DELETE dup
RETURN count(*) AS duplicates_removed;
