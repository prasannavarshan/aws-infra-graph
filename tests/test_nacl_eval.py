"""Tests for NACL lookup and evaluation."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

import pytest

from src.tools.nacl_eval import (
    evaluate_nacl_egress,
    evaluate_nacl_ingress,
    lookup_nacls_for_resource,
    lookup_nacls_for_sg,
)


def _make_nacl(
    nacl_id: str = "acl-abc123",
    name: str = "test-nacl",
    ingress: str = "Rule 100 ALLOW all:all 0.0.0.0/0",
    egress: str = "Rule 100 ALLOW all:all 0.0.0.0/0",
) -> dict:
    """Build a mock NACL dict."""
    return {
        "nacl_id": nacl_id,
        "name": name,
        "ingress": ingress,
        "egress": egress,
    }


# --- Lookup tests ---


class TestLookupNaclsForResource:
    """Tests for lookup_nacls_for_resource."""

    @pytest.mark.asyncio
    async def test_returns_nacls(self):
        """Finds NACLs via resource -> subnet -> NACL."""
        neo4j = AsyncMock()
        neo4j.query.return_value = [_make_nacl()]
        result = await lookup_nacls_for_resource(
            neo4j, "arn:aws:ec2:us-east-1:111:instance/i-abc",
        )
        assert len(result) == 1
        assert result[0]["nacl_id"] == "acl-abc123"

    @pytest.mark.asyncio
    async def test_returns_empty_when_no_nacls(self):
        """No NACLs found returns empty list."""
        neo4j = AsyncMock()
        neo4j.query.return_value = []
        result = await lookup_nacls_for_resource(
            neo4j, "arn:aws:lambda:us-east-1:111:function/fn",
        )
        assert result == []

    @pytest.mark.asyncio
    async def test_filters_empty_nacl_ids(self):
        """Skips results with empty nacl_id."""
        neo4j = AsyncMock()
        neo4j.query.return_value = [
            {"nacl_id": None, "name": "", "ingress": "", "egress": ""},
            _make_nacl(nacl_id="acl-real"),
        ]
        result = await lookup_nacls_for_resource(neo4j, "arn:test")
        assert len(result) == 1
        assert result[0]["nacl_id"] == "acl-real"


class TestLookupNaclsForSG:
    """Tests for lookup_nacls_for_sg."""

    @pytest.mark.asyncio
    async def test_returns_nacls_via_sg(self):
        """Finds NACLs via SG -> resource -> subnet -> NACL."""
        neo4j = AsyncMock()
        neo4j.query.return_value = [_make_nacl()]
        result = await lookup_nacls_for_sg(neo4j, "sg-abc123")
        assert len(result) == 1

    @pytest.mark.asyncio
    async def test_returns_empty(self):
        """No resources for SG returns empty NACLs."""
        neo4j = AsyncMock()
        neo4j.query.return_value = []
        result = await lookup_nacls_for_sg(neo4j, "sg-orphan")
        assert result == []


# --- Evaluation tests ---


class TestEvaluateNaclEgress:
    """Tests for evaluate_nacl_egress."""

    def test_allowed_by_rule(self):
        """Rule 100 ALLOW all matches."""
        nacls = [_make_nacl(
            egress="Rule 100 ALLOW all:all 0.0.0.0/0",
        )]
        ok, reason = evaluate_nacl_egress(
            nacls, 443, "tcp", "10.0.0.1",
        )
        assert ok is True
        assert "ALLOW" in reason

    def test_denied_by_rule(self):
        """Explicit deny before allow blocks."""
        nacls = [_make_nacl(
            egress=(
                "Rule 50 DENY tcp:443 0.0.0.0/0; "
                "Rule 100 ALLOW all:all 0.0.0.0/0"
            ),
        )]
        ok, reason = evaluate_nacl_egress(
            nacls, 443, "tcp", "10.0.0.1",
        )
        assert ok is False
        assert "DENY" in reason

    def test_no_nacls_default_allow(self):
        """No NACLs means default allow."""
        ok, reason = evaluate_nacl_egress([], 443, "tcp", "10.0.0.1")
        assert ok is True
        assert "default allow" in reason

    def test_implicit_deny(self):
        """No matching rule = implicit deny."""
        nacls = [_make_nacl(
            egress="Rule 100 ALLOW tcp:80 0.0.0.0/0",
        )]
        ok, reason = evaluate_nacl_egress(
            nacls, 443, "tcp", "10.0.0.1",
        )
        assert ok is False
        assert "implicit deny" in reason

    def test_cidr_mismatch_denied(self):
        """Rule with non-matching CIDR doesn't allow."""
        nacls = [_make_nacl(
            egress="Rule 100 ALLOW tcp:443 192.168.0.0/16",
        )]
        ok, reason = evaluate_nacl_egress(
            nacls, 443, "tcp", "10.0.0.1",
        )
        assert ok is False


class TestEvaluateNaclIngress:
    """Tests for evaluate_nacl_ingress."""

    def test_allowed_by_rule(self):
        """Rule 100 ALLOW matches."""
        nacls = [_make_nacl(
            ingress="Rule 100 ALLOW tcp:443 0.0.0.0/0",
        )]
        ok, reason = evaluate_nacl_ingress(
            nacls, 443, "tcp", "10.0.0.1",
        )
        assert ok is True

    def test_denied_by_rule(self):
        """Explicit deny blocks."""
        nacls = [_make_nacl(
            ingress="Rule 50 DENY tcp:443 10.0.0.0/8",
        )]
        ok, reason = evaluate_nacl_ingress(
            nacls, 443, "tcp", "10.0.0.1",
        )
        assert ok is False
        assert "DENY" in reason

    def test_no_nacls_default_allow(self):
        """No NACLs means default allow."""
        ok, reason = evaluate_nacl_ingress(
            [], 443, "tcp", "10.0.0.1",
        )
        assert ok is True

    def test_multiple_nacls_all_must_allow(self):
        """Multiple NACLs — one deny means denied."""
        nacls = [
            _make_nacl(
                nacl_id="acl-1",
                ingress="Rule 100 ALLOW tcp:443 0.0.0.0/0",
            ),
            _make_nacl(
                nacl_id="acl-2",
                ingress="Rule 50 DENY tcp:443 0.0.0.0/0",
            ),
        ]
        ok, reason = evaluate_nacl_ingress(
            nacls, 443, "tcp", "10.0.0.1",
        )
        assert ok is False
        assert "acl-2" in reason


# --- Integration: guided_connectivity with NACLs ---


class TestGuidedConnectivityNacl:
    """Tests for NACL integration in guided_connectivity_check."""

    def _make_ctx(self, neo4j: AsyncMock) -> MagicMock:
        ctx = MagicMock()
        app = MagicMock()
        app.neo4j = neo4j
        ctx.request_context.lifespan_context = app
        return ctx

    @pytest.mark.asyncio
    async def test_nacl_shown_in_output(self):
        """NACL analysis section appears when NACLs exist."""
        from src.tools.guided_connectivity import (
            guided_connectivity_check,
        )

        neo4j = AsyncMock()
        ctx = self._make_ctx(neo4j)

        src_resource = {
            "arn": "arn:lambda", "name": "my-lambda",
            "label": "LambdaFunction",
            "account_id": "111111111111", "region": "us-east-1",
        }
        tgt_resource = {
            "arn": "arn:eks", "name": "my-eks",
            "label": "EKSCluster",
            "account_id": "222222222222", "region": "us-east-1",
        }
        src_sg = {
            "group_id": "sg-src", "name": "lambda-sg",
            "vpc_id": "vpc-111", "account_id": "111111111111",
            "ingress": "", "egress": "all:all from 0.0.0.0/0",
        }
        tgt_sg = {
            "group_id": "sg-tgt", "name": "eks-node-sg",
            "vpc_id": "vpc-111", "account_id": "222222222222",
            "ingress": "tcp:443 from sg:sg-src", "egress": "",
        }
        src_nacl = _make_nacl(
            nacl_id="acl-src",
            egress="Rule 100 ALLOW all:all 0.0.0.0/0",
        )
        tgt_nacl = _make_nacl(
            nacl_id="acl-tgt",
            ingress="Rule 100 ALLOW tcp:443 0.0.0.0/0",
        )

        neo4j.query.side_effect = [
            [],                 # load_account_names
            [],                 # load_vpc_names
            [src_resource],     # resolve source
            [tgt_resource],     # resolve target
            [src_sg],           # source SGs
            [tgt_sg],           # target SGs
            [src_nacl],         # source NACLs
            [tgt_nacl],         # target NACLs
            [{"ip": "10.1.1.1"}],
            [{"ip": "10.2.2.2"}],
        ]

        result = await guided_connectivity_check(
            ctx,
            source="lambda my-lambda",
            target="eks my-eks",
            port=443,
            live_refresh=False,
        )
        assert "NACL Analysis:" in result
        assert "Source egress: ALLOWED" in result
        assert "Target ingress: ALLOWED" in result
        assert "Verdict: ALLOWED" in result
        assert "SG and NACL rules" in result

    @pytest.mark.asyncio
    async def test_nacl_denied_blocks_verdict(self):
        """NACL deny overrides SG allow."""
        from src.tools.guided_connectivity import (
            guided_connectivity_check,
        )

        neo4j = AsyncMock()
        ctx = self._make_ctx(neo4j)

        src_resource = {
            "arn": "arn:lambda", "name": "my-lambda",
            "label": "LambdaFunction",
            "account_id": "111111111111", "region": "us-east-1",
        }
        tgt_resource = {
            "arn": "arn:rds", "name": "my-rds",
            "label": "RDSInstance",
            "account_id": "111111111111", "region": "us-east-1",
        }
        src_sg = {
            "group_id": "sg-src", "name": "lambda-sg",
            "vpc_id": "vpc-111", "account_id": "111111111111",
            "ingress": "", "egress": "all:all from 0.0.0.0/0",
        }
        tgt_sg = {
            "group_id": "sg-tgt", "name": "rds-sg",
            "vpc_id": "vpc-111", "account_id": "111111111111",
            "ingress": "tcp:5432 from sg:sg-src",
            "egress": "",
        }
        # NACL blocks port 5432 outbound from source subnet
        src_nacl = _make_nacl(
            nacl_id="acl-src",
            egress=(
                "Rule 50 DENY tcp:5432 0.0.0.0/0; "
                "Rule 100 ALLOW all:all 0.0.0.0/0"
            ),
        )

        neo4j.query.side_effect = [
            [],                 # load_account_names
            [],                 # load_vpc_names
            [src_resource],
            [tgt_resource],
            [src_sg],
            [tgt_sg],
            [src_nacl],         # source NACLs (denies 5432)
            [],                 # target NACLs (none)
            [{"ip": "10.1.1.1"}],
            [{"ip": "10.2.2.2"}],
        ]

        result = await guided_connectivity_check(
            ctx,
            source="lambda my-lambda",
            target="rds my-rds",
            port=5432,
            live_refresh=False,
        )
        assert "Verdict: DENIED" in result
        assert "NACL Egress" in result
        assert "acl-src" in result


# --- Integration: check_sg_connectivity with NACLs ---


class TestSGConnectivityNacl:
    """Tests for NACL integration in check_sg_connectivity."""

    def _make_ctx(self, neo4j: AsyncMock) -> MagicMock:
        ctx = MagicMock()
        app = MagicMock()
        app.neo4j = neo4j
        ctx.request_context.lifespan_context = app
        return ctx

    @pytest.mark.asyncio
    async def test_nacl_shown_in_sg_tool(self):
        """NACL section appears in check_sg_connectivity."""
        from src.tools.sg_connectivity import (
            check_sg_connectivity,
        )

        neo4j = AsyncMock()
        ctx = self._make_ctx(neo4j)

        source = {
            "group_id": "sg-src", "name": "src-sg",
            "vpc_id": "vpc-111", "account_id": "111",
            "region": "us-east-1",
            "ingress": "", "egress": "all:all from 0.0.0.0/0",
        }
        target = {
            "group_id": "sg-tgt", "name": "tgt-sg",
            "vpc_id": "vpc-111", "account_id": "111",
            "region": "us-east-1",
            "ingress": "tcp:443 from sg:sg-src", "egress": "",
        }
        nacl = _make_nacl(
            nacl_id="acl-shared",
            ingress="Rule 100 ALLOW tcp:443 0.0.0.0/0",
            egress="Rule 100 ALLOW all:all 0.0.0.0/0",
        )

        neo4j.query.side_effect = [
            [],           # load_account_names
            [],           # load_vpc_names
            [source],     # resolve source SG
            [target],     # resolve target SG
            [],           # source IP direct miss
            [],           # source IP VPC fallback
            [],           # target IP direct miss
            [],           # target IP VPC fallback
            [nacl],       # source SG NACLs
            [nacl],       # target SG NACLs
        ]

        result = await check_sg_connectivity(
            ctx, "src-sg", "tgt-sg", port=443,
            live_refresh=False,
        )
        assert "NACL Analysis:" in result
        assert "Verdict: ALLOWED" in result
