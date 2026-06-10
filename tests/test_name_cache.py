"""Tests for name cache helpers."""

from __future__ import annotations

from unittest.mock import AsyncMock

import pytest

from src.tools.name_cache import (
    enrich_account,
    enrich_sg_reference,
    enrich_vpc,
    load_account_names,
    load_sg_names,
    load_vpc_names,
)


class TestLoadAccountNames:
    """Tests for load_account_names."""

    @pytest.mark.asyncio
    async def test_loads_map(self):
        """Returns id->name dict from graph."""
        neo4j = AsyncMock()
        neo4j.query.return_value = [
            {"id": "111", "name": "alpha"},
            {"id": "222", "name": "beta"},
        ]
        result = await load_account_names(neo4j)
        assert result == {"111": "alpha", "222": "beta"}

    @pytest.mark.asyncio
    async def test_empty_graph(self):
        """Returns empty dict when no accounts."""
        neo4j = AsyncMock()
        neo4j.query.return_value = []
        result = await load_account_names(neo4j)
        assert result == {}


class TestLoadVpcNames:
    """Tests for load_vpc_names."""

    @pytest.mark.asyncio
    async def test_loads_map(self):
        """Returns id->info dict from graph."""
        neo4j = AsyncMock()
        neo4j.query.return_value = [
            {
                "id": "vpc-111",
                "name": "my-vpc",
                "owner_id": "999",
            },
        ]
        result = await load_vpc_names(neo4j)
        assert result["vpc-111"]["name"] == "my-vpc"
        assert result["vpc-111"]["owner_id"] == "999"


class TestEnrichAccount:
    """Tests for enrich_account."""

    def test_with_name(self):
        """Shows name in parens."""
        names = {"111": "alpha"}
        assert enrich_account("111", names) == "111 (alpha)"

    def test_without_name(self):
        """Falls back to bare ID."""
        assert enrich_account("111", {}) == "111"

    def test_empty_id(self):
        """Empty ID returns unknown."""
        assert enrich_account("", {}) == "unknown"


class TestEnrichVpc:
    """Tests for enrich_vpc."""

    def test_with_name_and_owner(self):
        """Shows name and owner."""
        vpc_map = {
            "vpc-111": {
                "name": "my-vpc",
                "owner_id": "999",
            },
        }
        acct_names = {"999": "net-svc"}
        result = enrich_vpc(
            "vpc-111", vpc_map, acct_names,
        )
        assert "my-vpc" in result
        assert "owner: 999 (net-svc)" in result

    def test_without_owner(self):
        """Shows name only when no owner."""
        vpc_map = {
            "vpc-111": {"name": "my-vpc", "owner_id": ""},
        }
        result = enrich_vpc("vpc-111", vpc_map)
        assert result == "vpc-111 (my-vpc)"

    def test_unknown_vpc(self):
        """Falls back to bare ID."""
        assert enrich_vpc("vpc-999", {}) == "vpc-999"

    def test_empty_vpc(self):
        """Empty ID returns unknown."""
        assert enrich_vpc("", {}) == "unknown"


class TestLoadSgNames:
    """Tests for load_sg_names."""

    @pytest.mark.asyncio
    async def test_loads_map(self):
        """Returns group_id->name dict from graph."""
        neo4j = AsyncMock()
        neo4j.query.return_value = [
            {"id": "sg-aaa", "name": "my-sg"},
            {"id": "sg-bbb", "name": "other-sg"},
        ]
        result = await load_sg_names(neo4j)
        assert result == {
            "sg-aaa": "my-sg",
            "sg-bbb": "other-sg",
        }

    @pytest.mark.asyncio
    async def test_empty_graph(self):
        """Returns empty dict when no SGs."""
        neo4j = AsyncMock()
        neo4j.query.return_value = []
        result = await load_sg_names(neo4j)
        assert result == {}


class TestEnrichSgReference:
    """Tests for enrich_sg_reference."""

    def test_known_sg(self):
        """Enriches with name when known."""
        sg_names = {"sg-abc123": "my-sg-name"}
        result = enrich_sg_reference(
            "sg:sg-abc123", sg_names,
        )
        assert result == "sg:sg-abc123 (my-sg-name)"

    def test_unknown_sg(self):
        """Returns unchanged when SG not in map."""
        result = enrich_sg_reference("sg:sg-unknown", {})
        assert result == "sg:sg-unknown"

    def test_not_sg_ref(self):
        """Non-SG string returned unchanged."""
        result = enrich_sg_reference("10.0.0.0/8", {})
        assert result == "10.0.0.0/8"

    def test_empty_name(self):
        """Empty name in map returns unchanged."""
        sg_names = {"sg-abc": ""}
        result = enrich_sg_reference("sg:sg-abc", sg_names)
        assert result == "sg:sg-abc"
