"""Tests for EKS pod CIDR detection and SNAT logic."""

from __future__ import annotations

from unittest.mock import AsyncMock

import pytest

from src.tools.eks_pod_cidr import (
    _find_pod_cidr,
    is_target_in_vpc,
    lookup_eks_pod_cidr,
    lookup_vpc_cidrs,
    pick_sample_pod_ip,
)

# --- _find_pod_cidr ---


class TestFindPodCidr:
    """Tests for _find_pod_cidr helper."""

    def test_finds_100x_cidr(self):
        cidrs = ["10.1.0.0/16", "100.67.0.0/16"]
        assert _find_pod_cidr(cidrs) == "100.67.0.0/16"

    def test_returns_none_no_100x(self):
        cidrs = ["10.1.0.0/16", "172.16.0.0/12"]
        assert _find_pod_cidr(cidrs) is None

    def test_returns_first_match(self):
        cidrs = ["100.66.0.0/16", "100.67.0.0/16"]
        assert _find_pod_cidr(cidrs) == "100.66.0.0/16"

    def test_empty_list(self):
        assert _find_pod_cidr([]) is None

    def test_invalid_cidr_skipped(self):
        cidrs = ["not-a-cidr", "100.67.0.0/16"]
        assert _find_pod_cidr(cidrs) == "100.67.0.0/16"


# --- lookup_eks_pod_cidr ---


class TestLookupEksPodCidr:
    """Tests for lookup_eks_pod_cidr."""

    @pytest.mark.asyncio
    async def test_finds_pod_cidr_from_vpc(self):
        neo4j = AsyncMock()
        neo4j.query = AsyncMock(return_value=[{
            "secondary_cidrs": [
                "100.67.0.0/16",
            ],
        }])
        result = await lookup_eks_pod_cidr(neo4j, "arn:eks:cluster")
        assert result == "100.67.0.0/16"

    @pytest.mark.asyncio
    async def test_returns_none_no_secondary(self):
        neo4j = AsyncMock()
        neo4j.query = AsyncMock(return_value=[{
            "secondary_cidrs": None,
        }])
        result = await lookup_eks_pod_cidr(neo4j, "arn:eks:cluster")
        assert result is None

    @pytest.mark.asyncio
    async def test_returns_none_no_vpc_found(self):
        neo4j = AsyncMock()
        neo4j.query = AsyncMock(return_value=[])
        result = await lookup_eks_pod_cidr(neo4j, "arn:eks:cluster")
        assert result is None

    @pytest.mark.asyncio
    async def test_returns_none_no_100x(self):
        neo4j = AsyncMock()
        neo4j.query = AsyncMock(return_value=[{
            "secondary_cidrs": ["10.1.0.0/16"],
        }])
        result = await lookup_eks_pod_cidr(neo4j, "arn:eks:cluster")
        assert result is None


# --- lookup_vpc_cidrs ---


class TestLookupVpcCidrs:
    """Tests for lookup_vpc_cidrs."""

    @pytest.mark.asyncio
    async def test_returns_primary_and_secondary(self):
        neo4j = AsyncMock()
        neo4j.query = AsyncMock(return_value=[{
            "primary": "10.150.32.0/20",
            "secondary": ["100.67.0.0/16"],
        }])
        result = await lookup_vpc_cidrs(neo4j, "arn:eks:cluster")
        assert result == ["10.150.32.0/20", "100.67.0.0/16"]

    @pytest.mark.asyncio
    async def test_primary_only(self):
        neo4j = AsyncMock()
        neo4j.query = AsyncMock(return_value=[{
            "primary": "10.0.0.0/16",
            "secondary": None,
        }])
        result = await lookup_vpc_cidrs(neo4j, "arn:eks:cluster")
        assert result == ["10.0.0.0/16"]

    @pytest.mark.asyncio
    async def test_no_vpc(self):
        neo4j = AsyncMock()
        neo4j.query = AsyncMock(return_value=[])
        result = await lookup_vpc_cidrs(neo4j, "arn:eks:cluster")
        assert result == []


# --- is_target_in_vpc ---


class TestIsTargetInVpc:
    """Tests for is_target_in_vpc."""

    def test_target_in_primary_cidr(self):
        assert is_target_in_vpc(
            "10.150.34.5",
            ["10.150.32.0/20", "100.67.0.0/16"],
        )

    def test_target_in_secondary_cidr(self):
        assert is_target_in_vpc(
            "100.67.1.1",
            ["10.150.32.0/20", "100.67.0.0/16"],
        )

    def test_target_outside_all(self):
        assert not is_target_in_vpc(
            "172.16.0.1",
            ["10.150.32.0/20", "100.67.0.0/16"],
        )

    def test_empty_ip(self):
        assert not is_target_in_vpc("", ["10.0.0.0/8"])

    def test_empty_cidrs(self):
        assert not is_target_in_vpc("10.0.0.1", [])

    def test_invalid_ip(self):
        assert not is_target_in_vpc("bad-ip", ["10.0.0.0/8"])


# --- pick_sample_pod_ip ---


class TestPickSamplePodIp:
    """Tests for pick_sample_pod_ip."""

    def test_slash_16(self):
        ip = pick_sample_pod_ip("100.67.0.0/16")
        assert ip == "100.67.0.1"

    def test_slash_24(self):
        ip = pick_sample_pod_ip("100.67.1.0/24")
        assert ip == "100.67.1.1"

    def test_invalid_cidr(self):
        assert pick_sample_pod_ip("not-a-cidr") == ""

    def test_slash_32_returns_host(self):
        # /32 has exactly 1 host
        assert pick_sample_pod_ip("100.67.0.1/32") == "100.67.0.1"

    def test_slash_31_returns_first(self):
        # /31 has 2 hosts (point-to-point)
        ip = pick_sample_pod_ip("100.67.0.0/31")
        assert ip == "100.67.0.0"
