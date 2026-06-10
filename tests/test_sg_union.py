"""Tests for union SG evaluation in check_sg_connectivity."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

import pytest

from src.tools.sg_connectivity import check_sg_connectivity
from src.tools.sg_format import _format_verdict


def _make_sg(
    group_id: str = "sg-abc",
    name: str = "test-sg",
    vpc_id: str = "vpc-111",
    account_id: str = "123456789012",
    ingress: str = "tcp:443 from 0.0.0.0/0",
    egress: str = "all:all from 0.0.0.0/0",
) -> dict:
    return {
        "group_id": group_id,
        "name": name,
        "vpc_id": vpc_id,
        "account_id": account_id,
        "ingress": ingress,
        "egress": egress,
    }


def _make_ctx(neo4j: AsyncMock) -> MagicMock:
    ctx = MagicMock()
    app = MagicMock()
    app.neo4j = neo4j
    ctx.request_context.lifespan_context = app
    return ctx


def _side_effect_multi(
    sources: list[dict],
    targets: list[dict],
) -> list:
    """Build side_effect for multi-SG resolution.

    Order: load_account_names, load_vpc_names,
    then resolve queries for each source SG (1 query each),
    then resolve queries for each target SG (1 query each),
    then IP lookups (source tries each SG, target tries each),
    then NACL lookups (one per SG in each side).
    """
    effects: list = [
        [],  # load_account_names
        [],  # load_vpc_names
    ]
    # Each SG resolves via strategy 1 (one query)
    for sg in sources:
        effects.append([sg])
    for sg in targets:
        effects.append([sg])
    # IP lookups: miss for all SGs (2 queries each: direct + VPC)
    for _ in sources:
        effects.append([])  # direct miss
        effects.append([])  # VPC fallback miss
    for _ in targets:
        effects.append([])  # direct miss
        effects.append([])  # VPC fallback miss
    # NACL lookups: empty for all SGs
    for _ in sources:
        effects.append([])  # source SG NACLs
    for _ in targets:
        effects.append([])  # target SG NACLs
    return effects


class TestUnionSGAllowed:
    """Union evaluation: first SG denies, second allows."""

    @pytest.mark.asyncio
    async def test_second_source_sg_allows_egress(self):
        """First SG denies egress, second allows -> ALLOWED."""
        neo4j = AsyncMock()
        sg_deny = _make_sg(
            group_id="sg-deny",
            name="restrictive-sg",
            egress="tcp:80 from 10.0.0.0/8",
        )
        sg_allow = _make_sg(
            group_id="sg-allow",
            name="permissive-sg",
            egress="all:all from 0.0.0.0/0",
        )
        target = _make_sg(
            group_id="sg-tgt",
            name="target-sg",
            ingress="tcp:27017 from 0.0.0.0/0",
        )
        neo4j.query.side_effect = _side_effect_multi(
            [sg_deny, sg_allow], [target],
        )
        ctx = _make_ctx(neo4j)

        result = await check_sg_connectivity(
            ctx, "sg-deny,sg-allow", "sg-tgt",
            port=27017, live_refresh=False,
        )
        assert "Verdict: ALLOWED" in result

    @pytest.mark.asyncio
    async def test_sg_ref_matches_across_union(self):
        """Ingress rule refs sg-abc, which is one of source SGs."""
        neo4j = AsyncMock()
        sg_a = _make_sg(
            group_id="sg-aaa",
            name="cluster-sg",
            egress="all:all from 0.0.0.0/0",
        )
        sg_b = _make_sg(
            group_id="sg-bbb",
            name="managed-sg",
            egress="all:all from 0.0.0.0/0",
        )
        target = _make_sg(
            group_id="sg-tgt",
            name="mongodb-vpce",
            ingress="tcp:27017 from sg:sg-aaa",
        )
        neo4j.query.side_effect = _side_effect_multi(
            [sg_a, sg_b], [target],
        )
        ctx = _make_ctx(neo4j)

        result = await check_sg_connectivity(
            ctx, "sg-aaa,sg-bbb", "sg-tgt",
            port=27017, live_refresh=False,
        )
        assert "Verdict: ALLOWED" in result
        assert "SG match" in result


class TestUnionSGDenied:
    """Union evaluation: all SGs deny -> DENIED."""

    @pytest.mark.asyncio
    async def test_all_source_sgs_deny_egress(self):
        """Both source SGs deny egress -> DENIED."""
        neo4j = AsyncMock()
        sg_a = _make_sg(
            group_id="sg-aaa",
            name="sg-a",
            egress="tcp:80 from 10.0.0.0/8",
        )
        sg_b = _make_sg(
            group_id="sg-bbb",
            name="sg-b",
            egress="tcp:22 from 10.0.0.0/8",
        )
        target = _make_sg(
            group_id="sg-tgt",
            name="target-sg",
            ingress="tcp:27017 from 0.0.0.0/0",
        )
        neo4j.query.side_effect = _side_effect_multi(
            [sg_a, sg_b], [target],
        )
        ctx = _make_ctx(neo4j)

        result = await check_sg_connectivity(
            ctx, "sg-aaa,sg-bbb", "sg-tgt",
            port=27017, live_refresh=False,
        )
        assert "Verdict: DENIED" in result


class TestUnionSGBackwardCompat:
    """Single SG input produces identical behavior."""

    @pytest.mark.asyncio
    async def test_single_sg_output_unchanged(self):
        """Single SG input: output format is same as before."""
        neo4j = AsyncMock()
        source = _make_sg(
            group_id="sg-src",
            name="source-sg",
            egress="all:all from 0.0.0.0/0",
        )
        target = _make_sg(
            group_id="sg-tgt",
            name="target-sg",
            ingress="tcp:443 from sg:sg-src",
        )
        neo4j.query.side_effect = _side_effect_multi(
            [source], [target],
        )
        ctx = _make_ctx(neo4j)

        result = await check_sg_connectivity(
            ctx, "sg-src", "sg-tgt",
            port=443, live_refresh=False,
        )
        assert "SG Connectivity: source-sg -> target-sg" in result
        assert "Source: source-sg (sg-src)" in result
        assert "Target: target-sg (sg-tgt)" in result
        assert "Verdict: ALLOWED" in result


class TestUnionSGResolutionErrors:
    """Multi-SG resolution: one invalid SG names it in error."""

    @pytest.mark.asyncio
    async def test_invalid_sg_in_comma_list(self):
        """One valid + one invalid SG -> error names failing SG."""
        neo4j = AsyncMock()
        valid = _make_sg(group_id="sg-valid", name="valid-sg")
        neo4j.query.side_effect = [
            [],  # load_account_names
            [],  # load_vpc_names
            [valid],  # resolve sg-valid
            [],  # resolve bad-sg strategy 1
            [],  # resolve bad-sg strategy 3 (any token)
        ]
        ctx = _make_ctx(neo4j)

        result = await check_sg_connectivity(
            ctx, "sg-valid,bad-sg", "sg-tgt",
            live_refresh=False,
        )
        assert "Source SG error" in result
        assert "bad-sg" in result


class TestFormatVerdictMultiSG:
    """Tests for multi-SG display in _format_verdict."""

    def test_multi_source_header(self):
        """Multiple sources show '2 SGs (union)' in header."""
        src_a = _make_sg(group_id="sg-a", name="sg-a")
        src_b = _make_sg(group_id="sg-b", name="sg-b")
        tgt = _make_sg(group_id="sg-tgt", name="tgt")
        output = _format_verdict(
            [src_a, src_b], [tgt], 443, "tcp",
            True, "all:all from 0.0.0.0/0",
            True, "tcp:443 from sg:sg-a",
            cross_vpc=False,
            egress_sg_name="sg-b (sg-b)",
        )
        assert "2 SGs (union)" in output
        assert "Verdict: ALLOWED" in output

    def test_multi_source_denied_shows_all_count(self):
        """Multiple sources denied shows 'All N SGs' count."""
        src_a = _make_sg(group_id="sg-a", name="sg-a")
        src_b = _make_sg(group_id="sg-b", name="sg-b")
        tgt = _make_sg(group_id="sg-tgt", name="tgt")
        output = _format_verdict(
            [src_a, src_b], [tgt], 27017, "tcp",
            False, "no matching egress rule",
            True, "tcp:27017 from 0.0.0.0/0",
            cross_vpc=False,
        )
        assert "All 2 SGs: DENIED" in output
        assert "Verdict: DENIED" in output

    def test_single_sg_no_union_label(self):
        """Single SG does NOT show 'union' in header."""
        src = _make_sg(group_id="sg-a", name="src")
        tgt = _make_sg(group_id="sg-b", name="tgt")
        output = _format_verdict(
            [src], [tgt], 443, "tcp",
            True, "ok", True, "ok",
            cross_vpc=False,
        )
        assert "union" not in output
        assert "Source: src (sg-a)" in output
