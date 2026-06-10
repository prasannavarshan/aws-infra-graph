"""Tests for guided connectivity checker."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from src.tools.guided_connectivity import (
    _evaluate_eks_pod_cidr,
    _format_account_disambiguation,
    _format_disambiguation,
    _get_resource_sgs,
    guided_connectivity_check,
)
from src.tools.guided_resolve import (
    ResolvedResource,
    ResourceHint,
    _parse_resource_hint,
    _resolve_account,
    _resolve_resource,
)

# --- Helpers ---


def _make_resource_row(
    arn: str = "arn:aws:lambda:us-east-1:111:function:my-fn",
    name: str = "my-fn",
    label: str = "LambdaFunction",
    account_id: str = "111111111111",
    region: str = "us-east-1",
) -> dict:
    """Build a mock resource query result row."""
    return {
        "arn": arn,
        "name": name,
        "label": label,
        "account_id": account_id,
        "region": region,
    }


def _make_sg_row(
    group_id: str = "sg-abc123",
    name: str = "test-sg",
    vpc_id: str = "vpc-111",
    account_id: str = "111111111111",
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


def _make_ctx(neo4j: AsyncMock) -> MagicMock:
    """Build a mock MCP Context with neo4j."""
    ctx = MagicMock()
    app = MagicMock()
    app.neo4j = neo4j
    ctx.request_context.lifespan_context = app
    return ctx


# --- TestParseResourceHint ---


class TestParseResourceHint:
    """Tests for _parse_resource_hint."""

    def test_lambda_keyword_prefix(self):
        """Lambda keyword at start extracts label."""
        hint = _parse_resource_hint("lambda my-func")
        assert hint.label == "LambdaFunction"
        assert hint.name_query == "my-func"

    def test_eks_keyword_suffix(self):
        """EKS keyword at end extracts label."""
        hint = _parse_resource_hint("prod-api beta EKS")
        assert hint.label == "EKSCluster"
        assert hint.name_query == "prod-api beta"

    def test_no_keyword_fallback(self):
        """No keyword returns empty label."""
        hint = _parse_resource_hint("some-random-name")
        assert hint.label == ""
        assert hint.name_query == "some-random-name"

    def test_redis_keyword(self):
        """Redis keyword maps to ElastiCacheCluster."""
        hint = _parse_resource_hint("redis b-ae1-cache")
        assert hint.label == "ElastiCacheCluster"
        assert hint.name_query == "b-ae1-cache"

    def test_case_insensitive(self):
        """Keywords are case-insensitive."""
        hint = _parse_resource_hint("LAMBDA MY-FUNC")
        assert hint.label == "LambdaFunction"
        assert hint.name_query == "MY-FUNC"


# --- TestResolveAccount ---


class TestResolveAccount:
    """Tests for _resolve_account."""

    @pytest.mark.asyncio
    async def test_single_match(self):
        """Single account match returns account_id string."""
        neo4j = AsyncMock()
        neo4j.query.return_value = [
            {"id": "111111111111", "name": "beta-account"},
        ]
        result = await _resolve_account(neo4j, "beta")
        assert result == "111111111111"

    @pytest.mark.asyncio
    async def test_ambiguous(self):
        """Multiple matches returns candidate list."""
        neo4j = AsyncMock()
        neo4j.query.return_value = [
            {"id": "111111111111", "name": "beta-core"},
            {"id": "222222222222", "name": "beta-ops"},
        ]
        result = await _resolve_account(neo4j, "beta")
        assert isinstance(result, list)
        assert len(result) == 2

    @pytest.mark.asyncio
    async def test_not_found(self):
        """No match returns empty list."""
        neo4j = AsyncMock()
        neo4j.query.return_value = []
        result = await _resolve_account(neo4j, "nonexistent")
        assert result == []

    @pytest.mark.asyncio
    async def test_empty_hint(self):
        """Empty hint returns empty string."""
        neo4j = AsyncMock()
        result = await _resolve_account(neo4j, "")
        assert result == ""
        neo4j.query.assert_not_called()

    @pytest.mark.asyncio
    async def test_account_id_passthrough(self):
        """12-digit number returns as-is."""
        neo4j = AsyncMock()
        result = await _resolve_account(
            neo4j, "123456789012",
        )
        assert result == "123456789012"
        neo4j.query.assert_not_called()


# --- TestResolveResource ---


class TestResolveResource:
    """Tests for _resolve_resource."""

    @pytest.mark.asyncio
    async def test_single_match(self):
        """Single match returns ResolvedResource."""
        neo4j = AsyncMock()
        neo4j.query.return_value = [_make_resource_row()]
        hint = ResourceHint(
            label="LambdaFunction", name_query="my-fn",
        )
        result = await _resolve_resource(neo4j, hint)
        assert isinstance(result, ResolvedResource)
        assert result.name == "my-fn"

    @pytest.mark.asyncio
    async def test_disambiguation(self):
        """Multiple matches returns candidate list."""
        neo4j = AsyncMock()
        neo4j.query.return_value = [
            _make_resource_row(name="fn-a", arn="arn:a"),
            _make_resource_row(name="fn-b", arn="arn:b"),
        ]
        hint = ResourceHint(label="LambdaFunction", name_query="fn")
        result = await _resolve_resource(neo4j, hint)
        assert isinstance(result, list)
        assert len(result) == 2

    @pytest.mark.asyncio
    async def test_not_found(self):
        """Zero matches returns error string."""
        neo4j = AsyncMock()
        neo4j.query.return_value = []
        hint = ResourceHint(label="EKSCluster", name_query="nope")
        result = await _resolve_resource(neo4j, hint)
        assert isinstance(result, str)
        assert "No resource found" in result

    @pytest.mark.asyncio
    async def test_exact_name_wins(self):
        """Exact name match wins over substring matches."""
        neo4j = AsyncMock()
        neo4j.query.return_value = [
            _make_resource_row(name="my-fn", arn="arn:exact"),
            _make_resource_row(
                name="my-fn-extra", arn="arn:extra",
            ),
        ]
        hint = ResourceHint(
            label="LambdaFunction", name_query="my-fn",
        )
        result = await _resolve_resource(neo4j, hint)
        assert isinstance(result, ResolvedResource)
        assert result.arn == "arn:exact"

    @pytest.mark.asyncio
    async def test_multi_label_no_keyword(self):
        """Empty label searches across all SG-bearing types."""
        neo4j = AsyncMock()
        neo4j.query.return_value = [_make_resource_row()]
        hint = ResourceHint(label="", name_query="my-fn")
        result = await _resolve_resource(neo4j, hint)
        assert isinstance(result, ResolvedResource)
        # Verify the query didn't use a specific label
        call_args = neo4j.query.call_args
        query_str = call_args[0][0]
        assert "LambdaFunction OR" in query_str

    @pytest.mark.asyncio
    async def test_all_tokens_match(self):
        """Multi-token query matches via all-tokens strategy."""
        neo4j = AsyncMock()
        eks_row = _make_resource_row(
            arn="arn:eks:prod-api-beta",
            name="prod-api-beta-nv-1",
            label="EKSCluster",
        )
        neo4j.query.side_effect = [
            [],          # strategy 1: full substring miss
            [eks_row],   # strategy 2: all-tokens hit
        ]
        hint = ResourceHint(
            label="EKSCluster", name_query="dany beta",
        )
        result = await _resolve_resource(neo4j, hint)
        assert isinstance(result, ResolvedResource)
        assert result.name == "prod-api-beta-nv-1"
        assert neo4j.query.call_count == 2

    @pytest.mark.asyncio
    async def test_any_token_fallback(self):
        """Partial token match via any-token ranked strategy."""
        neo4j = AsyncMock()
        eks_row = _make_resource_row(
            arn="arn:eks:prod-api-beta",
            name="prod-api-beta-nv-1",
            label="EKSCluster",
        )
        neo4j.query.side_effect = [
            [],          # strategy 1: "prod-api beta" miss
            [],          # strategy 2: all-tokens miss
            [eks_row],   # strategy 3: "beta" token hit
        ]
        hint = ResourceHint(
            label="EKSCluster", name_query="prod-api beta",
        )
        result = await _resolve_resource(neo4j, hint)
        assert isinstance(result, ResolvedResource)
        assert result.name == "prod-api-beta-nv-1"
        assert neo4j.query.call_count == 3

    @pytest.mark.asyncio
    async def test_single_token_skips_all_tokens(self):
        """Single-word input skips strategy 2 (all-tokens)."""
        neo4j = AsyncMock()
        row = _make_resource_row(name="my-fn")
        neo4j.query.side_effect = [
            [],      # strategy 1: miss
            [row],   # strategy 3: any-token ranked
        ]
        hint = ResourceHint(
            label="LambdaFunction", name_query="my-fn-x",
        )
        result = await _resolve_resource(neo4j, hint)
        assert isinstance(result, ResolvedResource)
        # Only 2 calls: strategy 1 + strategy 3 (skipped 2)
        assert neo4j.query.call_count == 2

    @pytest.mark.asyncio
    async def test_full_substring_preferred(self):
        """Strategy 1 match means only 1 query call."""
        neo4j = AsyncMock()
        row = _make_resource_row(name="prod-api-beta-nv-1")
        neo4j.query.return_value = [row]
        hint = ResourceHint(
            label="EKSCluster", name_query="dany-beta",
        )
        result = await _resolve_resource(neo4j, hint)
        assert isinstance(result, ResolvedResource)
        assert neo4j.query.call_count == 1


# --- TestGetResourceSGs ---


class TestGetResourceSGs:
    """Tests for _get_resource_sgs."""

    @pytest.mark.asyncio
    async def test_standard_has_sg(self):
        """Lambda/EC2 returns SGs via direct HAS_SG."""
        neo4j = AsyncMock()
        neo4j.query.return_value = [_make_sg_row()]
        sgs, sg_type = await _get_resource_sgs(
            neo4j, "arn:aws:lambda:...", "LambdaFunction",
        )
        assert len(sgs) == 1
        assert sgs[0]["group_id"] == "sg-abc123"
        assert sg_type == "SGs"

    @pytest.mark.asyncio
    async def test_eks_worker_sgs(self):
        """EKS cluster returns worker SGs via nodegroup."""
        neo4j = AsyncMock()
        # First query (worker SGs) returns results
        neo4j.query.return_value = [
            _make_sg_row(
                group_id="sg-worker",
                name="eks-node-sg",
            ),
        ]
        sgs, sg_type = await _get_resource_sgs(
            neo4j, "arn:aws:eks:...", "EKSCluster",
        )
        assert len(sgs) == 1
        assert sgs[0]["group_id"] == "sg-worker"
        assert "worker" in sg_type

    @pytest.mark.asyncio
    async def test_eks_fallback_ctrl_plane(self):
        """EKS cluster falls back to control-plane SGs."""
        neo4j = AsyncMock()
        # Worker query returns empty, ctrl-plane returns SG
        neo4j.query.side_effect = [
            [],  # worker SGs
            [_make_sg_row(
                group_id="sg-ctrl",
                name="eks-cluster-sg",
            )],  # control-plane SGs
        ]
        sgs, sg_type = await _get_resource_sgs(
            neo4j, "arn:aws:eks:...", "EKSCluster",
        )
        assert len(sgs) == 1
        assert sgs[0]["group_id"] == "sg-ctrl"
        assert "control-plane" in sg_type

    @pytest.mark.asyncio
    async def test_no_sgs(self):
        """Resource with no SGs returns empty list."""
        neo4j = AsyncMock()
        neo4j.query.return_value = []
        sgs, sg_type = await _get_resource_sgs(
            neo4j, "arn:aws:lambda:...", "LambdaFunction",
        )
        assert sgs == []


# --- TestGuidedConnectivityCheck ---


class TestGuidedConnectivityCheck:
    """Tests for guided_connectivity_check orchestrator."""

    @pytest.mark.asyncio
    async def test_allowed_end_to_end(self):
        """Full flow: Lambda -> EKS, ALLOWED."""
        neo4j = AsyncMock()
        ctx = _make_ctx(neo4j)

        src_resource = _make_resource_row(
            arn="arn:lambda",
            name="my-lambda",
            label="LambdaFunction",
        )
        tgt_resource = _make_resource_row(
            arn="arn:eks",
            name="my-eks",
            label="EKSCluster",
            account_id="222222222222",
        )
        src_sg = _make_sg_row(
            group_id="sg-src",
            name="lambda-sg",
            egress="all:all from 0.0.0.0/0",
        )
        tgt_sg = _make_sg_row(
            group_id="sg-tgt",
            name="eks-node-sg",
            ingress="tcp:443 from sg:sg-src",
        )

        neo4j.query.side_effect = [
            [],                 # load_account_names
            [],                 # load_vpc_names
            [src_resource],     # resolve source resource
            [tgt_resource],     # resolve target resource
            [src_sg],           # source SGs (Lambda HAS_SG)
            [tgt_sg],           # target SGs (EKS worker)
            [],                 # source NACLs
            [],                 # target NACLs
            [{"ip": "10.1.1.1"}],  # source sample IP
            [{"ip": "10.2.2.2"}],  # target sample IP
        ]

        result = await guided_connectivity_check(
            ctx,
            source="lambda my-lambda",
            target="eks my-eks",
            port=443,
            live_refresh=False,
        )
        assert "ALLOWED" in result
        assert "my-lambda" in result
        assert "my-eks" in result

    @pytest.mark.asyncio
    async def test_denied(self):
        """Ingress denied returns DENIED verdict."""
        neo4j = AsyncMock()
        ctx = _make_ctx(neo4j)

        src_resource = _make_resource_row(
            arn="arn:lambda", name="my-lambda",
            label="LambdaFunction",
        )
        tgt_resource = _make_resource_row(
            arn="arn:eks", name="my-eks",
            label="EKSCluster",
            account_id="222222222222",
        )
        src_sg = _make_sg_row(
            group_id="sg-src", name="lambda-sg",
            egress="all:all from 0.0.0.0/0",
        )
        tgt_sg = _make_sg_row(
            group_id="sg-tgt", name="eks-node-sg",
            ingress="tcp:22 from 10.0.0.0/8",  # wrong port
        )

        neo4j.query.side_effect = [
            [],                 # load_account_names
            [],                 # load_vpc_names
            [src_resource],
            [tgt_resource],
            [src_sg],
            [tgt_sg],
            [],                 # source NACLs
            [],                 # target NACLs
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
        assert "DENIED" in result

    @pytest.mark.asyncio
    async def test_source_not_found(self):
        """Source not found returns error."""
        neo4j = AsyncMock()
        ctx = _make_ctx(neo4j)
        neo4j.query.return_value = []

        result = await guided_connectivity_check(
            ctx,
            source="lambda nonexistent",
            target="eks my-eks",
            live_refresh=False,
        )
        assert "Source:" in result
        assert "No resource found" in result

    @pytest.mark.asyncio
    async def test_target_disambiguation(self):
        """Multiple target matches returns disambiguation."""
        neo4j = AsyncMock()
        ctx = _make_ctx(neo4j)

        src_resource = _make_resource_row(
            arn="arn:lambda", name="my-lambda",
            label="LambdaFunction",
        )

        neo4j.query.side_effect = [
            [],              # load_account_names
            [],              # load_vpc_names
            [src_resource],  # resolve source
            [                # resolve target: ambiguous
                _make_resource_row(
                    arn="arn:eks1", name="eks-beta",
                    label="EKSCluster",
                ),
                _make_resource_row(
                    arn="arn:eks2", name="eks-prod",
                    label="EKSCluster",
                ),
            ],
        ]

        result = await guided_connectivity_check(
            ctx,
            source="lambda my-lambda",
            target="eks eks-",
            live_refresh=False,
        )
        assert "Multiple resources" in result
        assert "eks-beta" in result
        assert "eks-prod" in result

    @pytest.mark.asyncio
    async def test_account_filter(self):
        """Account filter narrows search."""
        neo4j = AsyncMock()
        ctx = _make_ctx(neo4j)

        acct_row = {"id": "222222222222", "name": "beta"}
        src_resource = _make_resource_row(
            arn="arn:lambda", name="my-lambda",
            label="LambdaFunction",
        )
        tgt_resource = _make_resource_row(
            arn="arn:eks", name="my-eks",
            label="EKSCluster",
            account_id="222222222222",
        )
        src_sg = _make_sg_row(
            group_id="sg-src", egress="all:all from 0.0.0.0/0",
        )
        tgt_sg = _make_sg_row(
            group_id="sg-tgt",
            ingress="tcp:443 from sg:sg-src",
        )

        neo4j.query.side_effect = [
            [],                 # load_account_names
            [],                 # load_vpc_names
            [acct_row],         # resolve target_account
            [src_resource],
            [tgt_resource],
            [src_sg],
            [tgt_sg],
            [],                 # source NACLs
            [],                 # target NACLs
            [{"ip": "10.1.1.1"}],
            [{"ip": "10.2.2.2"}],
        ]

        result = await guided_connectivity_check(
            ctx,
            source="lambda my-lambda",
            target="eks my-eks",
            target_account="beta",
            port=443,
            live_refresh=False,
        )
        assert "ALLOWED" in result

    @pytest.mark.asyncio
    async def test_no_sgs_on_source(self):
        """Source with no SGs returns error."""
        neo4j = AsyncMock()
        ctx = _make_ctx(neo4j)

        src_resource = _make_resource_row(
            arn="arn:lambda", name="my-lambda",
            label="LambdaFunction",
        )
        tgt_resource = _make_resource_row(
            arn="arn:eks", name="my-eks",
            label="EKSCluster",
        )

        neo4j.query.side_effect = [
            [],              # load_account_names
            [],              # load_vpc_names
            [src_resource],
            [tgt_resource],
            [],              # source SGs: empty
        ]

        result = await guided_connectivity_check(
            ctx,
            source="lambda my-lambda",
            target="eks my-eks",
            live_refresh=False,
        )
        assert "No security groups found" in result
        assert "my-lambda" in result

    @pytest.mark.asyncio
    async def test_account_disambiguation(self):
        """Ambiguous account returns disambiguation."""
        neo4j = AsyncMock()
        ctx = _make_ctx(neo4j)

        neo4j.query.return_value = [
            {"id": "111", "name": "beta-core"},
            {"id": "222", "name": "beta-ops"},
        ]

        result = await guided_connectivity_check(
            ctx,
            source="lambda my-fn",
            target="eks my-eks",
            source_account="beta",
            live_refresh=False,
        )
        assert "Multiple accounts" in result
        assert "beta-core" in result


# --- TestFormatDisambiguation ---


class TestFormatDisambiguation:
    """Tests for disambiguation formatters."""

    def test_resource_disambiguation(self):
        """Multiple candidates formatted correctly."""
        candidates = [
            _make_resource_row(name="fn-a", arn="arn:a"),
            _make_resource_row(name="fn-b", arn="arn:b"),
        ]
        output = _format_disambiguation("fn", candidates)
        assert "Multiple resources" in output
        assert "fn-a" in output
        assert "fn-b" in output

    def test_account_disambiguation(self):
        """Account candidates formatted correctly."""
        candidates = [
            {"id": "111", "name": "beta-core"},
            {"id": "222", "name": "beta-ops"},
        ]
        output = _format_account_disambiguation(
            "beta", candidates,
        )
        assert "Multiple accounts" in output
        assert "beta-core" in output


# --- TestLiveRefresh ---


class TestLiveRefresh:
    """Tests for live_refresh parameter."""

    @pytest.mark.asyncio
    async def test_live_refresh_calls_aws(self):
        """live_refresh=True triggers refresh and shows note."""
        neo4j = AsyncMock()
        ctx = _make_ctx(neo4j)

        src_resource = _make_resource_row(
            arn="arn:lambda", name="my-lambda",
            label="LambdaFunction",
        )
        tgt_resource = _make_resource_row(
            arn="arn:eks", name="my-eks",
            label="EKSCluster",
            account_id="222222222222",
        )
        src_sg = _make_sg_row(
            group_id="sg-src", name="lambda-sg",
            egress="all:all from 0.0.0.0/0",
        )
        tgt_sg = _make_sg_row(
            group_id="sg-tgt", name="eks-node-sg",
            ingress="tcp:443 from sg:sg-src",
        )

        neo4j.query.side_effect = [
            [],                 # load_account_names
            [],                 # load_vpc_names
            [src_resource],     # resolve source
            [tgt_resource],     # resolve target
            [src_sg],           # source SGs
            [tgt_sg],           # target SGs (EKS worker)
            [],                 # source NACLs
            [],                 # target NACLs
            [{"ip": "10.1.1.1"}],  # source sample IP
            [{"ip": "10.2.2.2"}],  # target sample IP
        ]

        # Mock refresh to return fresh SGs
        fresh_src = {
            "group_id": "sg-src",
            "name": "lambda-sg",
            "vpc_id": "vpc-111",
            "account_id": "111111111111",
            "ingress": "tcp:443 from 0.0.0.0/0",
            "egress": "all:all from 0.0.0.0/0",
        }
        fresh_tgt = {
            "group_id": "sg-tgt",
            "name": "eks-node-sg",
            "vpc_id": "vpc-111",
            "account_id": "222222222222",
            "ingress": "tcp:443 from sg:sg-src",
            "egress": "all:all from 0.0.0.0/0",
        }

        with patch(
            "src.tools.guided_connectivity"
            ".refresh_security_groups",
            new_callable=AsyncMock,
            return_value=[fresh_src, fresh_tgt],
        ) as mock_refresh:
            result = await guided_connectivity_check(
                ctx,
                source="lambda my-lambda",
                target="eks my-eks",
                port=443,
                live_refresh=True,
            )

        mock_refresh.assert_awaited_once()
        assert "SG rules refreshed from AWS" in result
        assert "ALLOWED" in result


class TestEksPodCidr:
    """Tests for EKS pod CIDR evaluation."""

    @pytest.mark.asyncio
    async def test_pod_cidr_denied_in_vpc(self):
        """Target in-VPC, pod CIDR ingress DENIED → warning."""
        neo4j = AsyncMock()
        source = ResolvedResource(
            arn="arn:eks", name="my-eks",
            label="EKSCluster",
            account_id="111", region="us-west-2",
        )
        tgt_sgs = [_make_sg_row(
            group_id="sg-tgt",
            ingress="tcp:443 from 10.150.32.0/20",
        )]
        # lookup_eks_pod_cidr query
        neo4j.query = AsyncMock(side_effect=[
            [{"secondary_cidrs": ["100.67.0.0/16"]}],
            [{"primary": "10.150.32.0/20",
              "secondary": ["100.67.0.0/16"]}],
        ])
        note, pod_ip = await _evaluate_eks_pod_cidr(
            neo4j, source, "10.150.41.5",
            tgt_sgs, 443, "tcp", frozenset({"sg-src"}),
        )
        assert "DENIED" in note
        assert "100.67.0.0/16" in note
        assert "no SNAT" in note
        assert pod_ip == "100.67.0.1"

    @pytest.mark.asyncio
    async def test_pod_cidr_allowed_in_vpc(self):
        """Target in-VPC, pod CIDR ingress ALLOWED → clean note."""
        neo4j = AsyncMock()
        source = ResolvedResource(
            arn="arn:eks", name="my-eks",
            label="EKSCluster",
            account_id="111", region="us-west-2",
        )
        tgt_sgs = [_make_sg_row(
            group_id="sg-tgt",
            ingress=(
                "tcp:443 from 10.150.32.0/20;"
                " tcp:443 from 100.67.0.0/16"
            ),
        )]
        neo4j.query = AsyncMock(side_effect=[
            [{"secondary_cidrs": ["100.67.0.0/16"]}],
            [{"primary": "10.150.32.0/20",
              "secondary": ["100.67.0.0/16"]}],
        ])
        note, pod_ip = await _evaluate_eks_pod_cidr(
            neo4j, source, "10.150.41.5",
            tgt_sgs, 443, "tcp", frozenset({"sg-src"}),
        )
        assert "ALLOWED" in note
        assert pod_ip == "100.67.0.1"

    @pytest.mark.asyncio
    async def test_snat_target_outside_vpc(self):
        """Target outside VPC → SNAT note, no pod eval."""
        neo4j = AsyncMock()
        source = ResolvedResource(
            arn="arn:eks", name="my-eks",
            label="EKSCluster",
            account_id="111", region="us-west-2",
        )
        tgt_sgs = [_make_sg_row(group_id="sg-tgt")]
        neo4j.query = AsyncMock(side_effect=[
            [{"secondary_cidrs": ["100.67.0.0/16"]}],
            [{"primary": "10.150.32.0/20",
              "secondary": ["100.67.0.0/16"]}],
        ])
        # Target IP is outside VPC CIDRs (on-prem)
        note, pod_ip = await _evaluate_eks_pod_cidr(
            neo4j, source, "172.16.0.1",
            tgt_sgs, 443, "tcp", frozenset({"sg-src"}),
        )
        assert "SNAT" in note
        assert "not evaluated" in note
        assert pod_ip == ""

    @pytest.mark.asyncio
    async def test_no_pod_cidr_no_note(self):
        """No pod CIDR on VPC → empty note, falls back."""
        neo4j = AsyncMock()
        source = ResolvedResource(
            arn="arn:eks", name="my-eks",
            label="EKSCluster",
            account_id="111", region="us-west-2",
        )
        tgt_sgs = [_make_sg_row(group_id="sg-tgt")]
        neo4j.query = AsyncMock(side_effect=[
            [{"secondary_cidrs": ["10.1.0.0/16"]}],
        ])
        note, pod_ip = await _evaluate_eks_pod_cidr(
            neo4j, source, "10.150.41.5",
            tgt_sgs, 443, "tcp", frozenset({"sg-src"}),
        )
        assert note == ""
        assert pod_ip == ""
