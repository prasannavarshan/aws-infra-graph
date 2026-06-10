"""Tests for DNS resolution trace tool."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

import pytest

from src.tools.dns_trace import (
    _trace_single,
    trace_dns,
)
from src.tools.dns_trace_queries import (
    detect_loopback,
    find_matching_rule,
    find_ns_delegation,
    longest_suffix_match,
    lookup_record,
    resolve_source_vpc,
)
from src.tools.dns_trace_resolve import (
    TraceResult,
    TraceStep,
    format_trace,
)


@pytest.fixture
def neo4j():
    """Mock Neo4j client."""
    return AsyncMock()


@pytest.fixture
def ctx():
    """Mock MCP context with neo4j client."""
    mock_ctx = MagicMock()
    mock_neo4j = AsyncMock()
    mock_ctx.request_context.lifespan_context.neo4j = mock_neo4j
    return mock_ctx, mock_neo4j


# --- resolve_source_vpc ---


@pytest.mark.asyncio
async def test_resolve_vpc_by_name(neo4j):
    """Happy path: VPC found by name."""
    neo4j.query.return_value = [{
        "vpc_id": "vpc-123",
        "name": "my-vpc",
        "account_id": "111111111111",
        "region": "us-east-1",
        "arn": "arn:aws:ec2:us-east-1:111111111111:vpc/vpc-123",
    }]
    result = await resolve_source_vpc(neo4j, "my-vpc", "")
    assert result is not None
    assert result["vpc_id"] == "vpc-123"


@pytest.mark.asyncio
async def test_resolve_vpc_not_found(neo4j):
    """Edge case: no VPC matches."""
    neo4j.query.return_value = []
    result = await resolve_source_vpc(neo4j, "nonexistent", "")
    assert result is None


@pytest.mark.asyncio
async def test_resolve_vpc_empty_input(neo4j):
    """Edge case: empty source_vpc."""
    result = await resolve_source_vpc(neo4j, "", "")
    assert result is None


# --- find_matching_rule ---


@pytest.mark.asyncio
async def test_find_rule_longest_suffix(neo4j):
    """Happy path: picks most specific rule."""
    neo4j.query.return_value = [
        {
            "name": "broad-rule",
            "domain_name": "example.com.",
            "rule_type": "FORWARD",
            "target_ips": ["10.0.0.1"],
            "endpoint_id": "rslvr-out-123",
            "owner_id": "111",
            "account_id": "111",
        },
        {
            "name": "specific-rule",
            "domain_name": "beta.prod.example.com.",
            "rule_type": "FORWARD",
            "target_ips": ["10.0.0.2"],
            "endpoint_id": "rslvr-out-456",
            "owner_id": "222",
            "account_id": "222",
        },
    ]
    result = await find_matching_rule(
        neo4j, "vpc-123", "app.beta.prod.example.com",
    )
    assert result is not None
    assert result["name"] == "specific-rule"


@pytest.mark.asyncio
async def test_find_rule_no_match(neo4j):
    """Edge case: no rule matches query."""
    neo4j.query.return_value = [
        {
            "name": "other-rule",
            "domain_name": "example.com.",
            "rule_type": "FORWARD",
            "target_ips": ["10.0.0.1"],
            "endpoint_id": "rslvr-out-123",
        },
    ]
    result = await find_matching_rule(
        neo4j, "vpc-123", "app.example.com",
    )
    assert result is None


@pytest.mark.asyncio
async def test_find_rule_no_rules(neo4j):
    """Error case: no rules in VPC."""
    neo4j.query.return_value = []
    result = await find_matching_rule(
        neo4j, "vpc-123", "anything.org",
    )
    assert result is None


# --- detect_loopback ---


@pytest.mark.asyncio
async def testdetect_loopback_found(neo4j):
    """Happy path: target IPs match inbound endpoint."""
    neo4j.query.return_value = [{
        "name": "inbound-ep",
        "arn": "arn:...",
        "endpoint_id": "rslvr-in-123",
        "ip_addresses": ["10.0.0.13", "10.0.0.57"],
        "vpc_id": "vpc-abc",
    }]
    result = await detect_loopback(
        neo4j, "vpc-abc", ["10.0.0.13", "10.0.0.80"],
    )
    assert result is not None
    assert result["endpoint_id"] == "rslvr-in-123"


@pytest.mark.asyncio
async def testdetect_loopback_not_found(neo4j):
    """Edge case: no inbound endpoint matches."""
    neo4j.query.return_value = [{
        "name": "inbound-ep",
        "endpoint_id": "rslvr-in-123",
        "ip_addresses": ["10.0.0.99"],
        "vpc_id": "vpc-abc",
    }]
    result = await detect_loopback(
        neo4j, "vpc-abc", ["10.0.0.13"],
    )
    assert result is None


@pytest.mark.asyncio
async def testdetect_loopback_no_inbound(neo4j):
    """Error case: no inbound endpoints in VPC."""
    neo4j.query.return_value = []
    result = await detect_loopback(
        neo4j, "vpc-abc", ["10.0.0.1"],
    )
    assert result is None


# --- longest_suffix_match ---


def test_longest_suffix_picks_most_specific():
    """Happy path: picks zone with most labels."""
    zones = [
        {"zone_name": "example.com.", "zone_id": "Z1"},
        {"zone_name": "beta.prod.example.com.", "zone_id": "Z2"},
        {"zone_name": "np.example.com.", "zone_id": "Z3"},
    ]
    winner, scored = longest_suffix_match(
        "app.beta.prod.example.com", zones,
    )
    assert winner is not None
    assert winner["zone_id"] == "Z2"
    # Check winner is marked
    winners = [s for s in scored if s[2]]
    assert len(winners) == 1
    assert winners[0][0] == "beta.prod.example.com"


def test_longest_suffix_no_match():
    """Edge case: no zone matches query."""
    zones = [
        {"zone_name": "other.com.", "zone_id": "Z1"},
    ]
    winner, scored = longest_suffix_match(
        "app.example.com", zones,
    )
    assert winner is None


def test_longest_suffix_empty_zones():
    """Error case: no zones at all."""
    winner, scored = longest_suffix_match("app.org", [])
    assert winner is None
    assert scored == []


# --- lookup_record ---


@pytest.mark.asyncio
async def testlookup_record_found(neo4j):
    """Happy path: exact record match."""
    neo4j.query.return_value = [{
        "name": "app.beta.prod.example.com.",
        "record_type": "A",
        "values": ["10.0.0.1"],
        "alias_target": None,
        "alias_zone_id": None,
        "ttl": 300,
    }]
    result = await lookup_record(
        neo4j, "Z123", "app.beta.prod.example.com",
    )
    assert result is not None
    assert result["record_type"] == "A"


@pytest.mark.asyncio
async def testlookup_record_wildcard(neo4j):
    """Edge case: wildcard record match."""
    # First call (exact) returns empty, second (wildcard) returns match
    neo4j.query.side_effect = [
        [],
        [{
            "name": "*.beta.prod.example.com.",
            "record_type": "A",
            "values": ["10.0.0.99"],
            "alias_target": None,
            "alias_zone_id": None,
            "ttl": 300,
        }],
    ]
    result = await lookup_record(
        neo4j, "Z123", "app.beta.prod.example.com",
    )
    assert result is not None
    assert result["name"] == "*.beta.prod.example.com."


@pytest.mark.asyncio
async def testlookup_record_not_found(neo4j):
    """Error case: no record in zone."""
    neo4j.query.return_value = []
    result = await lookup_record(
        neo4j, "Z123", "missing.example.com",
    )
    assert result is None


# --- format_trace ---


def testformat_trace_basic():
    """Happy path: formats trace result."""
    result = TraceResult(
        query_name="app.example.com",
        source_vpc_name="my-vpc",
        source_account="111111111111",
        steps=[
            TraceStep(
                title="Step 1: Resolver Rule Match",
                lines=["Rule: my-rule", "Domain: example.com."],
            ),
        ],
        verdict="RESOLVED (A)",
        verdict_detail="-> 10.0.0.1",
    )
    output = format_trace(result)
    assert "app.example.com" in output
    assert "my-vpc" in output
    assert "RESOLVED (A)" in output
    assert "10.0.0.1" in output


def testformat_trace_no_source():
    """Edge case: no source VPC."""
    result = TraceResult(
        query_name="test.com",
        verdict="PUBLIC DNS",
    )
    output = format_trace(result)
    assert "test.com" in output
    assert "Source:" not in output


# --- trace_dns (integration) ---


@pytest.mark.asyncio
async def test_trace_dns_no_vpc_no_auto(ctx):
    """Error case: no VPC specified and auto-detect fails."""
    mock_ctx, mock_neo4j = ctx
    mock_neo4j.query.return_value = []
    result = await trace_dns(mock_ctx, "test.example.com")
    assert "No source VPC specified" in result


@pytest.mark.asyncio
async def test_trace_dns_vpc_not_found(ctx):
    """Error case: specified VPC doesn't exist."""
    mock_ctx, mock_neo4j = ctx
    mock_neo4j.query.return_value = []
    result = await trace_dns(
        mock_ctx, "test.com", source_vpc="bad-vpc",
    )
    assert "Could not find VPC" in result


@pytest.mark.asyncio
async def test_trace_dns_public_fallback(ctx):
    """Happy path: no rule match, no private zones → public DNS."""
    mock_ctx, mock_neo4j = ctx
    # First call: resolve VPC, second: find rules (empty),
    # third: find private zones (empty)
    mock_neo4j.query.side_effect = [
        [{  # VPC lookup
            "vpc_id": "vpc-123",
            "name": "test-vpc",
            "account_id": "111",
            "region": "us-east-1",
            "arn": "arn:...",
        }],
        [],  # No matching rules
        [],  # No private zones on source VPC
    ]
    result = await trace_dns(
        mock_ctx, "unknown.domain.com", source_vpc="test-vpc",
    )
    assert "PUBLIC DNS" in result


@pytest.mark.asyncio
async def test_trace_no_rule_but_private_zone_resolves(neo4j):
    """No forwarding rule, but source VPC has a matching private zone."""
    neo4j.query.side_effect = [
        [],  # Step 1: no matching rules
        # Private zones on source VPC
        [{
            "zone_name": "pe.jfrog.io.",
            "zone_id": "Z999",
            "arn": "arn:aws:route53:::hostedzone/Z999",
            "account_id": "624819241886",
            "record_count": 3,
        }],
        # Step 5: record lookup (exact)
        [{
            "name": "pe.jfrog.io.",
            "record_type": "A",
            "values": ["10.200.0.1"],
            "alias_target": None,
            "alias_zone_id": None,
            "ttl": 300,
        }],
    ]
    result = await _trace_single(
        neo4j, "pe.jfrog.io",
        "vpc-123", "test-vpc", "111",
    )
    assert result.verdict == "RESOLVED (A)"
    assert "10.200.0.1" in result.verdict_detail


@pytest.mark.asyncio
async def test_trace_no_rule_private_zone_no_match(neo4j):
    """No forwarding rule, source VPC has zones but none match."""
    neo4j.query.side_effect = [
        [],  # Step 1: no matching rules
        # Private zones on source VPC (none match query)
        [{
            "zone_name": "other.internal.",
            "zone_id": "Z888",
            "arn": "arn:...",
            "account_id": "111",
            "record_count": 2,
        }],
    ]
    result = await _trace_single(
        neo4j, "pe.jfrog.io",
        "vpc-123", "test-vpc", "111",
    )
    assert result.verdict == "PUBLIC DNS"


# --- _trace_single edge cases ---


@pytest.mark.asyncio
async def test_trace_cname_depth_limit(neo4j):
    """Error case: CNAME chain exceeds max depth."""
    result = await _trace_single(
        neo4j, "deep.example.com",
        "vpc-123", "test-vpc", "111",
        depth=11,
    )
    assert result.verdict == "ERROR"
    assert "max depth" in result.verdict_detail


@pytest.mark.asyncio
async def test_trace_nxdomain(neo4j):
    """Edge case: zone exists but no record → NXDOMAIN."""
    neo4j.query.side_effect = [
        # Step 1: matching rule
        [{
            "name": "my-rule",
            "domain_name": "example.com.",
            "rule_type": "FORWARD",
            "target_ips": ["10.0.0.1"],
            "endpoint_id": "rslvr-out-123",
            "owner_id": "111",
            "account_id": "111",
        }],
        # Step 2: outbound endpoint
        [{
            "name": "outbound-ep",
            "arn": "arn:...",
            "endpoint_id": "rslvr-out-123",
            "vpc_id": "vpc-abc",
            "ip_addresses": ["10.0.0.5"],
            "vpc_name": "dns-vpc",
            "vpc_cidr": "10.0.0.0/24",
        }],
        # Step 3: loopback detected
        [{
            "name": "inbound-ep",
            "arn": "arn:...",
            "endpoint_id": "rslvr-in-456",
            "ip_addresses": ["10.0.0.1"],
            "vpc_id": "vpc-abc",
        }],
        # Step 4: private zones
        [{
            "zone_name": "example.com.",
            "zone_id": "Z123",
            "arn": "arn:...",
            "account_id": "111",
            "record_count": 5,
        }],
        # Step 5: record lookup (exact) — not found
        [],
        # Step 5: record lookup (wildcard) — not found
        [],
        # NS delegation check — not found
        [],
    ]
    result = await _trace_single(
        neo4j, "missing.example.com",
        "vpc-123", "test-vpc", "111",
    )
    assert result.verdict == "NXDOMAIN"
    assert "authoritative" in result.verdict_detail


# --- NS delegation ---


@pytest.mark.asyncio
async def testfind_ns_delegation_found(neo4j):
    """Happy path: NS delegation record exists."""
    neo4j.query.return_value = [{
        "name": "sub.example.com.",
        "values": ["ns-1.awsdns.org.", "ns-2.awsdns.net."],
    }]
    result = await find_ns_delegation(
        neo4j, "Z123", "example.com",
        "app.sub.example.com",
    )
    assert result is not None
    assert result["name"] == "sub.example.com."


@pytest.mark.asyncio
async def testfind_ns_delegation_not_found(neo4j):
    """Edge case: no NS delegation."""
    neo4j.query.return_value = []
    result = await find_ns_delegation(
        neo4j, "Z123", "example.com",
        "app.example.com",
    )
    assert result is None


@pytest.mark.asyncio
async def test_trace_ns_delegation_resolved(neo4j):
    """Happy path: NS delegation leads to record."""
    neo4j.query.side_effect = [
        # Step 1: matching rule
        [{
            "name": "my-rule",
            "domain_name": "example.com.",
            "rule_type": "FORWARD",
            "target_ips": ["10.0.0.1"],
            "endpoint_id": "rslvr-out-123",
            "owner_id": "111",
            "account_id": "111",
        }],
        # Step 2: outbound endpoint
        [{
            "name": "outbound-ep",
            "arn": "arn:...",
            "endpoint_id": "rslvr-out-123",
            "vpc_id": "vpc-abc",
            "ip_addresses": ["10.0.0.5"],
            "vpc_name": "dns-vpc",
            "vpc_cidr": "10.0.0.0/24",
        }],
        # Step 3: loopback detected
        [{
            "name": "inbound-ep",
            "arn": "arn:...",
            "endpoint_id": "rslvr-in-456",
            "ip_addresses": ["10.0.0.1"],
            "vpc_id": "vpc-abc",
        }],
        # Step 4: private zones
        [{
            "zone_name": "example.com.",
            "zone_id": "Z100",
            "arn": "arn:...",
            "account_id": "111",
            "record_count": 5,
        }],
        # Step 5: record lookup (exact) — not found
        [],
        # Step 5: record lookup (wildcard) — not found
        [],
        # NS delegation check — found!
        [{
            "name": "sub.example.com.",
            "values": ["ns-1.awsdns.org."],
        }],
        # Resolve delegation zone
        [{
            "zone_id": "Z200",
            "zone_name": "sub.example.com.",
            "account_id": "222",
            "is_private": True,
        }],
        # Record lookup in delegated zone (exact)
        [{
            "name": "app.sub.example.com.",
            "record_type": "A",
            "values": ["10.1.1.1"],
            "alias_target": None,
            "alias_zone_id": None,
            "ttl": 300,
        }],
    ]
    result = await _trace_single(
        neo4j, "app.sub.example.com",
        "vpc-123", "test-vpc", "111",
    )
    assert result.verdict == "RESOLVED (A)"
    assert "10.1.1.1" in result.verdict_detail


@pytest.mark.asyncio
async def test_trace_ns_delegation_zone_not_in_graph(neo4j):
    """Edge case: delegation target zone not in graph."""
    neo4j.query.side_effect = [
        # Step 1: matching rule
        [{
            "name": "my-rule",
            "domain_name": "example.com.",
            "rule_type": "FORWARD",
            "target_ips": ["10.0.0.1"],
            "endpoint_id": "rslvr-out-123",
            "owner_id": "111",
            "account_id": "111",
        }],
        # Step 2: outbound endpoint
        [{
            "name": "outbound-ep",
            "arn": "arn:...",
            "endpoint_id": "rslvr-out-123",
            "vpc_id": "vpc-abc",
            "ip_addresses": ["10.0.0.5"],
            "vpc_name": "dns-vpc",
            "vpc_cidr": "10.0.0.0/24",
        }],
        # Step 3: loopback detected
        [{
            "name": "inbound-ep",
            "arn": "arn:...",
            "endpoint_id": "rslvr-in-456",
            "ip_addresses": ["10.0.0.1"],
            "vpc_id": "vpc-abc",
        }],
        # Step 4: private zones
        [{
            "zone_name": "example.com.",
            "zone_id": "Z100",
            "arn": "arn:...",
            "account_id": "111",
            "record_count": 5,
        }],
        # Step 5: record lookup (exact) — not found
        [],
        # Step 5: record lookup (wildcard) — not found
        [],
        # NS delegation check — found
        [{
            "name": "ext.example.com.",
            "values": ["ns-ext.corp.net."],
        }],
        # Resolve delegation zone — not in graph
        [],
    ]
    result = await _trace_single(
        neo4j, "app.ext.example.com",
        "vpc-123", "test-vpc", "111",
    )
    assert result.verdict == "DELEGATED"
    assert "not in graph" in result.verdict_detail
