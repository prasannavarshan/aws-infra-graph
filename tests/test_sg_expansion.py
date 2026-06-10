"""Tests for deep SG expansion in get_resource_security_groups."""

from __future__ import annotations

from unittest.mock import AsyncMock

import pytest

from src.tools.resource_sgs import (
    _extract_sg_references,
    _fetch_referenced_sgs,
    _format_referenced_section,
)

# --- Helpers ---


def _make_sg(
    group_id: str = "sg-abc123",
    name: str = "test-sg",
    ingress: str = "tcp:443 from sg:sg-ref1",
    egress: str = "all:all from 0.0.0.0/0",
) -> dict:
    return {
        "group_id": group_id,
        "name": name,
        "vpc_id": "vpc-111",
        "account_id": "111111111111",
        "ingress": ingress,
        "egress": egress,
    }


# --- _extract_sg_references ---


class TestExtractSgReferences:
    """Tests for _extract_sg_references."""

    def test_finds_refs_from_rules(self):
        """Extracts sg-xxx references from ingress/egress."""
        sgs = [_make_sg(
            ingress="tcp:443 from sg:sg-ref1,sg:sg-ref2",
            egress="all:all from sg:sg-ref3",
        )]
        refs = _extract_sg_references(sgs)
        assert refs == {"sg-ref1", "sg-ref2", "sg-ref3"}

    def test_excludes_self_refs(self):
        """Self-referencing SGs are excluded."""
        sgs = [_make_sg(
            group_id="sg-self",
            ingress="tcp:443 from sg:sg-self,sg:sg-other",
        )]
        refs = _extract_sg_references(sgs)
        assert "sg-self" not in refs
        assert "sg-other" in refs

    def test_no_references(self):
        """No SG references returns empty set."""
        sgs = [_make_sg(
            ingress="tcp:443 from 10.0.0.0/8",
            egress="all:all from 0.0.0.0/0",
        )]
        refs = _extract_sg_references(sgs)
        assert refs == set()

    def test_deduplicates_across_sgs(self):
        """Same ref in multiple SGs is deduplicated."""
        sgs = [
            _make_sg(
                group_id="sg-a",
                ingress="tcp:443 from sg:sg-shared",
                egress="all:all from 0.0.0.0/0",
            ),
            _make_sg(
                group_id="sg-b",
                ingress="tcp:80 from 10.0.0.0/8",
                egress="all:all from sg:sg-shared",
            ),
        ]
        refs = _extract_sg_references(sgs)
        assert refs == {"sg-shared"}

    def test_excludes_all_own_ids(self):
        """All SG IDs in the input set are excluded."""
        sgs = [
            _make_sg(
                group_id="sg-a",
                ingress="tcp:443 from sg:sg-b",
            ),
            _make_sg(
                group_id="sg-b",
                ingress="tcp:80 from sg:sg-a",
            ),
        ]
        refs = _extract_sg_references(sgs)
        assert refs == set()


# --- _fetch_referenced_sgs ---


class TestFetchReferencedSgs:
    """Tests for _fetch_referenced_sgs."""

    @pytest.mark.asyncio
    async def test_returns_sgs(self):
        """Fetches SGs from graph by group_id."""
        neo4j = AsyncMock()
        neo4j.query.return_value = [
            {
                "group_id": "sg-ref1",
                "name": "ref-sg-1",
                "vpc_id": "vpc-111",
                "account_id": "111",
                "ingress": "tcp:443 from 0.0.0.0/0",
                "egress": "all:all from 0.0.0.0/0",
            },
        ]
        result = await _fetch_referenced_sgs(
            neo4j, {"sg-ref1"},
        )
        assert len(result) == 1
        assert result[0]["group_id"] == "sg-ref1"

    @pytest.mark.asyncio
    async def test_empty_ids_returns_empty(self):
        """Empty ID set returns empty without querying."""
        neo4j = AsyncMock()
        result = await _fetch_referenced_sgs(neo4j, set())
        assert result == []
        neo4j.query.assert_not_called()


# --- _format_referenced_section ---


class TestFormatReferencedSection:
    """Tests for _format_referenced_section."""

    def test_produces_section_header(self):
        """Output includes section header with count."""
        ref_sgs = [_make_sg(
            group_id="sg-ref1", name="ref-sg-1",
        )]
        output = _format_referenced_section(
            ref_sgs, {}, {},
        )
        assert "Referenced Security Groups (1)" in output
        assert "sg-ref1" in output
        assert "ref-sg-1" in output

    def test_multiple_referenced_sgs(self):
        """Multiple SGs formatted with indices."""
        ref_sgs = [
            _make_sg(group_id="sg-r1", name="r1"),
            _make_sg(group_id="sg-r2", name="r2"),
        ]
        output = _format_referenced_section(
            ref_sgs, {}, {},
        )
        assert "Referenced Security Groups (2)" in output
        assert "sg-r1" in output
        assert "sg-r2" in output

    def test_sg_names_enrichment(self):
        """SG name enrichment applied to referenced SGs."""
        ref_sgs = [_make_sg(
            group_id="sg-ref1",
            name="ref-sg-1",
            ingress="tcp:443 from sg:sg-other",
        )]
        sg_names = {"sg-other": "other-sg-name"}
        output = _format_referenced_section(
            ref_sgs, {}, {}, sg_names,
        )
        assert "other-sg-name" in output
