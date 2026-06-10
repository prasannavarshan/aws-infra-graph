# Bug: DNS trace skips private hosted zones on source VPC when no resolver rule matches

## Date
2026-03-17

## Severity
Medium — produces incorrect `PUBLIC DNS` verdict for domains resolved via cross-account private hosted zones.

## Summary
When `_trace_single()` finds no matching FORWARD resolver rule for a query, it immediately returns `PUBLIC DNS` without checking whether the source VPC has private hosted zones that could resolve the query. This misses cross-account private zones associated with the VPC (e.g., `pe.jfrog.io` associated via RAM from another account).

## Reproduction
1. Trace DNS for `pe.jfrog.io` from a VPC with no matching resolver rule:
   ```
   trace_dns("pe.jfrog.io", source_vpc="my-app-vpc")
   ```
2. Result: `PUBLIC DNS — No private resolver rule -- falls through to public DNS`
3. Expected: `RESOLVED` via private hosted zone `pe.jfrog.io.` (zone associated with the VPC via cross-account RAM share)

## Root Cause
In `src/tools/dns_trace.py`, `_trace_single()` lines 68-73:

```python
rule = await find_matching_rule(neo4j, vpc_id, query_name)
if not rule:
    # Immediately returns PUBLIC DNS — never checks VPC private zones
    result.verdict = "PUBLIC DNS"
    return result
```

The Route53 Resolver precedence is:
1. Resolver rules (FORWARD)
2. **Private hosted zones associated with the VPC** ← this step is skipped
3. Public DNS (recursive)

The private zone check (`find_private_zones`) only runs in step 4 after the loopback path, against the *landing* VPC. It is never run against the *source* VPC when no forwarding rule exists.

## AWS CLI Validation
```bash
# Confirms pe.jfrog.io private zone IS associated with the VPC
aws route53 list-hosted-zones-by-vpc \
  --vpc-id vpc-<your-vpc-id> \
  --vpc-region us-east-1 \
  --profile YOUR_AWS_PROFILE \
  --region us-east-1

# Output includes zone associated via RAM share from the owning account
```

## Fix Applied
**File:** `src/tools/dns_trace.py` — `_trace_single()`

When no forwarding rule matches, now checks private hosted zones on the source VPC before falling through to public DNS. Reuses existing `find_private_zones()`, `_handle_step4()` (longest-suffix match), and `_handle_step5()` (record lookup) — no new functions needed.

```
Before:  no rule → PUBLIC DNS (immediate return)
After:   no rule → check source VPC private zones → match? → resolve : PUBLIC DNS
```

Correctly implements Route53 Resolver precedence:
1. Resolver rules (FORWARD)
2. Private hosted zones on the VPC ← was skipped, now fixed
3. Public DNS (recursive fallback)

**No functionality lost:**
- `mode="public"` path (`_trace_public`) is untouched — separate code path
- `auto_detect_vpc` still works — only triggers when `source_vpc` is omitted, finds VPCs by resolver rule match
- Forwarding rule path unchanged — fix only affects the "no rule" branch
- Fallback to `PUBLIC DNS` preserved when no private zone matches either

**Tests added** in `tests/test_dns_trace.py`:
- `test_trace_no_rule_but_private_zone_resolves` — no rule, zone matches → RESOLVED
- `test_trace_no_rule_private_zone_no_match` — no rule, zone exists but doesn't match → PUBLIC DNS
- Updated `test_trace_dns_public_fallback` — accounts for new private zone query (returns empty)

All 28 tests pass.
