"""Tests for SG-to-SG connectivity checker."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

import pytest

from src.tools.sg_connectivity import (
    _dedup_by_group_id,
    _find_cidr_rules,
    _lookup_sample_ip,
    _resolve_sg,
    check_sg_connectivity,
)
from src.tools.sg_format import _format_verdict


def _make_sg_row(
    group_id: str = "sg-abc123",
    name: str = "test-sg",
    vpc_id: str = "vpc-111",
    account_id: str = "123456789012",
    ingress: str = "tcp:443 from 0.0.0.0/0",
    egress: str = "all:all from 0.0.0.0/0",
) -> dict:
    """Build a mock SG query result row."""
    return {
        "group_id": group_id,
        "name": name,
        "vpc_id": vpc_id,
        "account_id": account_id,
        "ingress": ingress,
        "egress": egress,
    }


# side_effect helper: name caches, resolve_src, resolve_tgt,
# IP lookups, then NACL lookups
def _side_effect(
    src: dict,
    tgt: dict,
    src_ip: str = "",
    tgt_ip: str = "",
    src_nacls: list | None = None,
    tgt_nacls: list | None = None,
) -> list:
    """Build side_effect list for neo4j.query calls.

    Order: load_account_names, load_vpc_names,
    resolve_src, resolve_tgt, IP lookups, NACL lookups.
    Each IP lookup tries direct SG first, then VPC fallback.
    """
    effects: list = [
        [],  # load_account_names
        [],  # load_vpc_names
        [src],
        [tgt],
    ]
    # Source IP lookup: direct SG query
    if src_ip:
        effects.append([{"ip": src_ip}])
    else:
        effects.append([])  # direct SG miss
        effects.append([])  # VPC fallback miss
    # Target IP lookup: direct SG query
    if tgt_ip:
        effects.append([{"ip": tgt_ip}])
    else:
        effects.append([])  # direct SG miss
        effects.append([])  # VPC fallback miss
    # NACL lookups (one per SG in each side)
    effects.append(src_nacls or [])  # source SG NACLs
    effects.append(tgt_nacls or [])  # target SG NACLs
    return effects


class TestResolveSG:
    """Tests for _resolve_sg helper."""

    @pytest.mark.asyncio
    async def test_resolve_by_group_id(self):
        """Exact sg-xxx match returns dict."""
        neo4j = AsyncMock()
        row = _make_sg_row(group_id="sg-abc123")
        neo4j.query.return_value = [row]

        result = await _resolve_sg(neo4j, "sg-abc123")
        assert isinstance(result, dict)
        assert result["group_id"] == "sg-abc123"

    @pytest.mark.asyncio
    async def test_resolve_by_name(self):
        """Exact name match returns dict."""
        neo4j = AsyncMock()
        row = _make_sg_row(name="eks-node-sg")
        neo4j.query.return_value = [row]

        result = await _resolve_sg(neo4j, "eks-node-sg")
        assert isinstance(result, dict)
        assert result["name"] == "eks-node-sg"

    @pytest.mark.asyncio
    async def test_resolve_ambiguous(self):
        """Multiple matches returns error with candidates."""
        neo4j = AsyncMock()
        neo4j.query.return_value = [
            _make_sg_row(
                group_id="sg-aaa", name="eks-node-sg-prod",
            ),
            _make_sg_row(
                group_id="sg-bbb", name="eks-node-sg-dev",
            ),
        ]

        result = await _resolve_sg(neo4j, "eks-node")
        assert isinstance(result, str)
        assert "Multiple security groups" in result
        assert "sg-aaa" in result
        assert "sg-bbb" in result

    @pytest.mark.asyncio
    async def test_resolve_not_found(self):
        """No matches returns error string."""
        neo4j = AsyncMock()
        neo4j.query.return_value = []

        result = await _resolve_sg(neo4j, "nonexistent-sg")
        assert isinstance(result, str)
        assert "No security group found" in result

    @pytest.mark.asyncio
    async def test_resolve_ambiguous_but_exact_name(self):
        """Multiple substring matches but exact name deduplicates."""
        neo4j = AsyncMock()
        neo4j.query.return_value = [
            _make_sg_row(
                group_id="sg-aaa", name="redis-sg",
            ),
            _make_sg_row(
                group_id="sg-bbb", name="redis-sg-replica",
            ),
        ]

        result = await _resolve_sg(neo4j, "redis-sg")
        assert isinstance(result, dict)
        assert result["group_id"] == "sg-aaa"


class TestLookupSampleIp:
    """Tests for _lookup_sample_ip helper."""

    @pytest.mark.asyncio
    async def test_returns_ip_when_found(self):
        neo4j = AsyncMock()
        neo4j.query.return_value = [{"ip": "10.150.170.42"}]
        ip = await _lookup_sample_ip(neo4j, "sg-abc123")
        assert ip == "10.150.170.42"

    @pytest.mark.asyncio
    async def test_vpc_fallback_when_no_direct_match(self):
        """Falls back to VPC-based lookup when no HAS_SG match."""
        neo4j = AsyncMock()
        # First query (direct SG) returns empty, second (VPC) finds IP
        neo4j.query.side_effect = [[], [{"ip": "10.150.170.99"}]]
        ip = await _lookup_sample_ip(
            neo4j, "sg-orphan", vpc_id="vpc-123",
        )
        assert ip == "10.150.170.99"
        assert neo4j.query.call_count == 2

    @pytest.mark.asyncio
    async def test_no_vpc_fallback_without_vpc_id(self):
        """No VPC fallback when vpc_id not provided."""
        neo4j = AsyncMock()
        neo4j.query.return_value = []
        ip = await _lookup_sample_ip(neo4j, "sg-orphan")
        assert ip == ""
        assert neo4j.query.call_count == 1

    @pytest.mark.asyncio
    async def test_returns_empty_when_no_resources(self):
        neo4j = AsyncMock()
        neo4j.query.return_value = []
        ip = await _lookup_sample_ip(neo4j, "sg-orphan")
        assert ip == ""


class TestCheckSGConnectivity:
    """Tests for the check_sg_connectivity tool."""

    def _make_ctx(self, neo4j: AsyncMock) -> MagicMock:
        """Build a mock MCP Context."""
        ctx = MagicMock()
        app = MagicMock()
        app.neo4j = neo4j
        ctx.request_context.lifespan_context = app
        return ctx

    @pytest.mark.asyncio
    async def test_allowed_by_sg_reference(self):
        """Ingress rule sg:sg-xxx matches source SG ID."""
        neo4j = AsyncMock()
        source = _make_sg_row(
            group_id="sg-src",
            name="eks-node-sg",
            egress="all:all from 0.0.0.0/0",
        )
        target = _make_sg_row(
            group_id="sg-tgt",
            name="redis-sg",
            ingress="tcp:6379 from sg:sg-src",
        )
        neo4j.query.side_effect = _side_effect(source, target)
        ctx = self._make_ctx(neo4j)

        result = await check_sg_connectivity(
            ctx, "eks-node-sg", "redis-sg", port=6379,
            live_refresh=False,
        )
        assert "Verdict: ALLOWED" in result
        assert "SG match" in result

    @pytest.mark.asyncio
    async def test_allowed_by_cidr_wildcard(self):
        """Egress all:all from 0.0.0.0/0 allows."""
        neo4j = AsyncMock()
        source = _make_sg_row(
            group_id="sg-src",
            name="source-sg",
            egress="all:all from 0.0.0.0/0",
        )
        target = _make_sg_row(
            group_id="sg-tgt",
            name="target-sg",
            ingress="tcp:443 from 0.0.0.0/0",
        )
        neo4j.query.side_effect = _side_effect(source, target)
        ctx = self._make_ctx(neo4j)

        result = await check_sg_connectivity(
            ctx, "source-sg", "target-sg", port=443,
            live_refresh=False,
        )
        assert "Verdict: ALLOWED" in result

    @pytest.mark.asyncio
    async def test_allowed_by_cidr_with_sample_ip(self):
        """CIDR rule matches when sample IP is available."""
        neo4j = AsyncMock()
        source = _make_sg_row(
            group_id="sg-src",
            name="eks-node",
            egress="all:all from 0.0.0.0/0",
        )
        target = _make_sg_row(
            group_id="sg-tgt",
            name="redis-sg",
            ingress="tcp:6379 from 10.0.0.0/8",
        )
        # Source IP 10.150.170.42 is in 10.0.0.0/8
        neo4j.query.side_effect = _side_effect(
            source, target, src_ip="10.150.170.42",
        )
        ctx = self._make_ctx(neo4j)

        result = await check_sg_connectivity(
            ctx, "eks-node", "redis-sg", port=6379,
            live_refresh=False,
        )
        assert "Verdict: ALLOWED" in result
        assert "sample IP: 10.150.170.42" in result

    @pytest.mark.asyncio
    async def test_denied_cidr_no_ip_shows_note(self):
        """CIDR rule can't match without IP, note shown."""
        neo4j = AsyncMock()
        source = _make_sg_row(
            group_id="sg-src",
            name="source-sg",
            egress="all:all from 0.0.0.0/0",
        )
        target = _make_sg_row(
            group_id="sg-tgt",
            name="target-sg",
            ingress="tcp:6379 from 10.0.0.0/8",
        )
        # No sample IPs available
        neo4j.query.side_effect = _side_effect(source, target)
        ctx = self._make_ctx(neo4j)

        result = await check_sg_connectivity(
            ctx, "source-sg", "target-sg", port=6379,
            live_refresh=False,
        )
        assert "Verdict: DENIED" in result
        assert "NOTE: CIDR rules exist (10.0.0.0/8)" in result

    @pytest.mark.asyncio
    async def test_denied_no_ingress_rule(self):
        """No matching ingress rule -> DENIED."""
        neo4j = AsyncMock()
        source = _make_sg_row(
            group_id="sg-src",
            name="source-sg",
            egress="all:all from 0.0.0.0/0",
        )
        target = _make_sg_row(
            group_id="sg-tgt",
            name="target-sg",
            ingress="tcp:443 from 10.0.0.0/8",
        )
        neo4j.query.side_effect = _side_effect(source, target)
        ctx = self._make_ctx(neo4j)

        result = await check_sg_connectivity(
            ctx, "source-sg", "target-sg", port=6379,
            live_refresh=False,
        )
        assert "Verdict: DENIED" in result
        assert "SG Ingress on sg-tgt" in result

    @pytest.mark.asyncio
    async def test_cross_vpc_warning(self):
        """Different vpc_ids triggers warning."""
        neo4j = AsyncMock()
        source = _make_sg_row(
            group_id="sg-src",
            name="source-sg",
            vpc_id="vpc-aaa",
            egress="all:all from 0.0.0.0/0",
        )
        target = _make_sg_row(
            group_id="sg-tgt",
            name="target-sg",
            vpc_id="vpc-bbb",
            ingress="tcp:443 from sg:sg-src",
        )
        neo4j.query.side_effect = _side_effect(source, target)
        ctx = self._make_ctx(neo4j)

        result = await check_sg_connectivity(
            ctx, "source-sg", "target-sg", port=443,
            live_refresh=False,
        )
        assert "WARNING" in result
        assert "different VPCs" in result

    @pytest.mark.asyncio
    async def test_end_to_end(self):
        """Full tool call with both SGs resolving and IPs."""
        neo4j = AsyncMock()
        source = _make_sg_row(
            group_id="sg-eks",
            name="eks-workers",
            vpc_id="vpc-shared",
            account_id="111111111111",
            egress="all:all from 0.0.0.0/0",
        )
        target = _make_sg_row(
            group_id="sg-redis",
            name="redis-cluster",
            vpc_id="vpc-shared",
            account_id="111111111111",
            ingress="tcp:6379 from sg:sg-eks",
        )
        neo4j.query.side_effect = _side_effect(
            source, target,
            src_ip="10.150.170.42",
            tgt_ip="10.150.170.210",
        )
        ctx = self._make_ctx(neo4j)

        result = await check_sg_connectivity(
            ctx, "eks-workers", "redis-cluster",
            port=6379, protocol="tcp",
            live_refresh=False,
        )
        assert "SG Connectivity: eks-workers -> redis-cluster" in result
        assert "TCP/6379" in result
        assert "Verdict: ALLOWED" in result
        assert "sg-eks" in result
        assert "sg-redis" in result
        assert "vpc-shared" in result
        assert "sample IP: 10.150.170.42" in result

    @pytest.mark.asyncio
    async def test_source_not_found(self):
        """Source SG not found returns error."""
        neo4j = AsyncMock()
        neo4j.query.return_value = []
        ctx = self._make_ctx(neo4j)

        result = await check_sg_connectivity(
            ctx, "nonexistent", "redis-sg",
            live_refresh=False,
        )
        assert "Source SG error" in result

    @pytest.mark.asyncio
    async def test_target_not_found(self):
        """Target SG not found returns error."""
        neo4j = AsyncMock()
        source = _make_sg_row(group_id="sg-src", name="src-sg")
        neo4j.query.side_effect = [
            [],  # load_account_names
            [],  # load_vpc_names
            [source],  # resolve source (strategy 1)
            [],  # target strategy 1: not found
            [],  # target strategy 3: any-token ranked
        ]
        ctx = self._make_ctx(neo4j)

        result = await check_sg_connectivity(
            ctx, "src-sg", "nonexistent",
            live_refresh=False,
        )
        assert "Target SG error" in result

    @pytest.mark.asyncio
    async def test_denied_egress_blocked(self):
        """Egress blocked -> DENIED even if ingress allows."""
        neo4j = AsyncMock()
        source = _make_sg_row(
            group_id="sg-src",
            name="locked-sg",
            egress="tcp:80 from 10.0.0.0/8",
        )
        target = _make_sg_row(
            group_id="sg-tgt",
            name="open-sg",
            ingress="tcp:443 from 0.0.0.0/0",
        )
        neo4j.query.side_effect = _side_effect(source, target)
        ctx = self._make_ctx(neo4j)

        result = await check_sg_connectivity(
            ctx, "locked-sg", "open-sg", port=443,
            live_refresh=False,
        )
        assert "Verdict: DENIED" in result
        assert "SG Egress on sg-src" in result


class TestFormatVerdict:
    """Tests for _format_verdict output formatting."""

    def test_allowed_output(self):
        src = _make_sg_row(group_id="sg-a", name="src")
        tgt = _make_sg_row(group_id="sg-b", name="tgt")
        output = _format_verdict(
            [src], [tgt], 443, "tcp",
            True, "all:all from 0.0.0.0/0",
            True, "tcp:443 from sg:sg-a (SG match)",
            cross_vpc=False,
        )
        assert "Verdict: ALLOWED" in output
        assert "WARNING" not in output

    def test_denied_output(self):
        src = _make_sg_row(group_id="sg-a", name="src")
        tgt = _make_sg_row(group_id="sg-b", name="tgt")
        output = _format_verdict(
            [src], [tgt], 6379, "tcp",
            True, "all:all from 0.0.0.0/0",
            False, "no rule for TCP/6379 from ",
            cross_vpc=False,
        )
        assert "Verdict: DENIED" in output
        assert "SG Ingress on sg-b" in output

    def test_sample_ip_shown(self):
        src = _make_sg_row(group_id="sg-a", name="src")
        tgt = _make_sg_row(group_id="sg-b", name="tgt")
        output = _format_verdict(
            [src], [tgt], 443, "tcp",
            True, "all:all from 0.0.0.0/0",
            True, "tcp:443 from 10.0.0.0/8",
            cross_vpc=False,
            source_ip="10.150.1.1",
            target_ip="10.150.2.2",
        )
        assert "sample IP: 10.150.1.1" in output
        assert "sample IP: 10.150.2.2" in output


class TestDedupByGroupId:
    """Tests for shared-VPC SG deduplication."""

    def test_dedup_same_group_id_different_accounts(self):
        """Same group_id in multiple accounts collapses to one."""
        rows = [
            _make_sg_row(
                group_id="sg-aaa", account_id="111",
            ),
            _make_sg_row(
                group_id="sg-aaa", account_id="222",
            ),
            _make_sg_row(
                group_id="sg-bbb", account_id="111",
            ),
        ]
        result = _dedup_by_group_id(rows)
        assert len(result) == 2
        ids = [r["group_id"] for r in result]
        assert ids == ["sg-aaa", "sg-bbb"]

    def test_dedup_no_duplicates(self):
        """No duplicates returns unchanged list."""
        rows = [
            _make_sg_row(group_id="sg-aaa"),
            _make_sg_row(group_id="sg-bbb"),
        ]
        result = _dedup_by_group_id(rows)
        assert len(result) == 2

    def test_dedup_empty(self):
        """Empty list returns empty."""
        assert _dedup_by_group_id([]) == []


class TestResolveSGWithAccount:
    """Tests for _resolve_sg with account_id filter."""

    @pytest.mark.asyncio
    async def test_resolve_with_account_id(self):
        """Account filter narrows to single match."""
        neo4j = AsyncMock()
        row = _make_sg_row(
            group_id="sg-aaa",
            name="prod_sg",
            account_id="111111111111",
        )
        neo4j.query.return_value = [row]

        result = await _resolve_sg(
            neo4j, "prod_sg", account_id="111111111111",
        )
        assert isinstance(result, dict)
        assert result["group_id"] == "sg-aaa"
        call_params = neo4j.query.call_args[0][1]
        assert call_params["account_id"] == "111111111111"

    @pytest.mark.asyncio
    async def test_shared_vpc_dedup_resolves(self):
        """Same SG in shared VPC (same group_id) deduplicates."""
        neo4j = AsyncMock()
        neo4j.query.return_value = [
            _make_sg_row(
                group_id="sg-aaa",
                name="prod_sg",
                account_id="111111111111",
            ),
            _make_sg_row(
                group_id="sg-aaa",
                name="prod_sg",
                account_id="732313447068",
            ),
        ]

        result = await _resolve_sg(neo4j, "prod_sg")
        assert isinstance(result, dict)
        assert result["group_id"] == "sg-aaa"

    @pytest.mark.asyncio
    async def test_exact_name_dedup_across_accounts(self):
        """Exact name with same group_id across accounts resolves."""
        neo4j = AsyncMock()
        neo4j.query.return_value = [
            _make_sg_row(
                group_id="sg-aaa",
                name="my-sg",
                account_id="111",
            ),
            _make_sg_row(
                group_id="sg-aaa",
                name="my-sg",
                account_id="222",
            ),
            _make_sg_row(
                group_id="sg-bbb",
                name="my-sg-extra",
                account_id="111",
            ),
        ]

        result = await _resolve_sg(neo4j, "my-sg")
        assert isinstance(result, dict)
        assert result["group_id"] == "sg-aaa"


class TestResolveSGTokenStrategies:
    """Tests for multi-token SG resolution strategies."""

    @pytest.mark.asyncio
    async def test_resolve_all_tokens(self):
        """Multi-token name matches via all-tokens strategy."""
        neo4j = AsyncMock()
        sg = _make_sg_row(
            group_id="sg-aaa",
            name="eks-node-beta-sg",
        )
        neo4j.query.side_effect = [
            [],     # strategy 1: "node beta" miss
            [sg],   # strategy 2: all-tokens hit
        ]
        result = await _resolve_sg(neo4j, "node beta")
        assert isinstance(result, dict)
        assert result["group_id"] == "sg-aaa"
        assert neo4j.query.call_count == 2

    @pytest.mark.asyncio
    async def test_resolve_any_token_fallback(self):
        """Partial token match via any-token ranked."""
        neo4j = AsyncMock()
        sg = _make_sg_row(
            group_id="sg-aaa",
            name="eks-node-beta-sg",
        )
        neo4j.query.side_effect = [
            [],     # strategy 1: "nodegroup beta" miss
            [],     # strategy 2: all-tokens miss
            [sg],   # strategy 3: "beta" token hit
        ]
        result = await _resolve_sg(neo4j, "nodegroup beta")
        assert isinstance(result, dict)
        assert result["group_id"] == "sg-aaa"
        assert neo4j.query.call_count == 3


class TestFindCidrRules:
    """Tests for CIDR rule detection helper."""

    def test_finds_matching_cidr(self):
        rules = "tcp:6379 from 10.0.0.0/8; tcp:443 from 0.0.0.0/0"
        cidrs = _find_cidr_rules(rules, 6379, "tcp")
        assert cidrs == ["10.0.0.0/8"]

    def test_skips_wildcard_cidrs(self):
        rules = "all:all from 0.0.0.0/0"
        cidrs = _find_cidr_rules(rules, 443, "tcp")
        assert cidrs == []

    def test_skips_sg_references(self):
        rules = "tcp:6379 from sg:sg-abc123"
        cidrs = _find_cidr_rules(rules, 6379, "tcp")
        assert cidrs == []

    def test_wrong_port_excluded(self):
        rules = "tcp:443 from 10.0.0.0/8"
        cidrs = _find_cidr_rules(rules, 6379, "tcp")
        assert cidrs == []

    def test_all_protocol_matches(self):
        rules = "all:all from 172.16.0.0/12"
        cidrs = _find_cidr_rules(rules, 6379, "tcp")
        assert cidrs == ["172.16.0.0/12"]


class TestSplitAccountIds:
    """Tests for separate source/target account IDs."""

    def _make_ctx(self, neo4j: AsyncMock) -> MagicMock:
        ctx = MagicMock()
        app = MagicMock()
        app.neo4j = neo4j
        ctx.request_context.lifespan_context = app
        return ctx

    @pytest.mark.asyncio
    async def test_separate_accounts(self):
        """Source and target in different accounts both resolve."""
        neo4j = AsyncMock()
        source = _make_sg_row(
            group_id="sg-src",
            name="eks-node",
            account_id="111",
        )
        target = _make_sg_row(
            group_id="sg-tgt",
            name="redis-sg",
            account_id="222",
            ingress="tcp:6379 from sg:sg-src",
        )
        neo4j.query.side_effect = _side_effect(source, target)
        ctx = self._make_ctx(neo4j)

        result = await check_sg_connectivity(
            ctx, "eks-node", "redis-sg",
            port=6379,
            source_account_id="111",
            target_account_id="222",
            live_refresh=False,
        )
        assert "Verdict: ALLOWED" in result
        calls = neo4j.query.call_args_list
        # calls[0]=acct_names, [1]=vpc_names, [2]=resolve_src, [3]=resolve_tgt
        assert calls[2][0][1]["account_id"] == "111"
        assert calls[3][0][1]["account_id"] == "222"

    @pytest.mark.asyncio
    async def test_target_account_independent(self):
        """target_account_id is independent from source."""
        neo4j = AsyncMock()
        source = _make_sg_row(
            group_id="sg-src", name="src",
        )
        target = _make_sg_row(
            group_id="sg-tgt", name="tgt",
            ingress="tcp:443 from 0.0.0.0/0",
        )
        neo4j.query.side_effect = _side_effect(source, target)
        ctx = self._make_ctx(neo4j)

        await check_sg_connectivity(
            ctx, "src", "tgt",
            source_account_id="111",
            live_refresh=False,
        )
        calls = neo4j.query.call_args_list
        # calls[0]=acct_names, [1]=vpc_names, [2]=resolve_src, [3]=resolve_tgt
        assert calls[2][0][1]["account_id"] == "111"
        assert "account_id" not in calls[3][0][1]


class TestLiveRefresh:
    """Tests for live_refresh parameter."""

    def _make_ctx(self, neo4j: AsyncMock) -> MagicMock:
        ctx = MagicMock()
        app = MagicMock()
        app.neo4j = neo4j
        ctx.request_context.lifespan_context = app
        return ctx

    @pytest.mark.asyncio
    async def test_live_refresh_calls_aws(self):
        """live_refresh=True triggers refresh and shows note."""
        from unittest.mock import patch

        neo4j = AsyncMock()
        source = _make_sg_row(
            group_id="sg-src",
            name="src-sg",
            egress="all:all from 0.0.0.0/0",
        )
        target = _make_sg_row(
            group_id="sg-tgt",
            name="tgt-sg",
            ingress="tcp:443 from sg:sg-src",
        )
        neo4j.query.side_effect = _side_effect(
            source, target,
        )
        ctx = self._make_ctx(neo4j)

        fresh_src = {
            "group_id": "sg-src",
            "name": "src-sg",
            "vpc_id": "vpc-111",
            "account_id": "123456789012",
            "ingress": "tcp:443 from 0.0.0.0/0",
            "egress": "all:all from 0.0.0.0/0",
        }
        fresh_tgt = {
            "group_id": "sg-tgt",
            "name": "tgt-sg",
            "vpc_id": "vpc-111",
            "account_id": "123456789012",
            "ingress": "tcp:443 from sg:sg-src",
            "egress": "all:all from 0.0.0.0/0",
        }

        with patch(
            "src.tools.sg_resolve"
            ".refresh_security_groups",
            new_callable=AsyncMock,
            return_value=[fresh_src, fresh_tgt],
        ) as mock_refresh:
            result = await check_sg_connectivity(
                ctx, "src-sg", "tgt-sg",
                port=443,
                live_refresh=True,
            )

        # Called twice: once for sources, once for targets
        assert mock_refresh.await_count == 2
        assert "SG rules refreshed from AWS" in result
        assert "ALLOWED" in result
