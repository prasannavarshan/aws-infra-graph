"""Tests for prefix list support in SG rules."""

from __future__ import annotations

from unittest.mock import MagicMock

from botocore.exceptions import ClientError

from src.collector.ec2_helpers import (
    _resolve_prefix_list,
    summarize_rules,
)
from src.tools.connectivity import _check_sg_allows, _parse_sg_rules
from src.tools.sg_connectivity import _find_cidr_rules

# --- _resolve_prefix_list ---


class TestResolvePrefixList:
    """Tests for _resolve_prefix_list."""

    def test_resolves_cidrs(self):
        """Happy path: returns CIDRs from paginated response."""
        client = MagicMock()
        paginator = MagicMock()
        paginator.paginate.return_value = [
            {
                "Entries": [
                    {"Cidr": "10.0.0.0/8"},
                    {"Cidr": "172.16.0.0/12"},
                ],
            },
        ]
        client.get_paginator.return_value = paginator

        result = _resolve_prefix_list(client, "pl-abc123")
        assert result == ["10.0.0.0/8", "172.16.0.0/12"]

    def test_client_error_returns_empty(self):
        """ClientError returns empty list gracefully."""
        client = MagicMock()
        paginator = MagicMock()
        paginator.paginate.side_effect = ClientError(
            {"Error": {"Code": "InvalidPrefixListId"}},
            "GetManagedPrefixListEntries",
        )
        client.get_paginator.return_value = paginator

        result = _resolve_prefix_list(client, "pl-bad")
        assert result == []

    def test_empty_entries(self):
        """Empty entries returns empty list."""
        client = MagicMock()
        paginator = MagicMock()
        paginator.paginate.return_value = [{"Entries": []}]
        client.get_paginator.return_value = paginator

        result = _resolve_prefix_list(client, "pl-empty")
        assert result == []


# --- summarize_rules with prefix lists ---


class TestSummarizeRulesWithPrefixLists:
    """Tests for summarize_rules prefix list handling."""

    def _make_pl_permission(
        self,
        pl_id: str = "pl-abc123",
        desc: str = "",
        proto: str = "tcp",
        from_port: int = 443,
        to_port: int = 443,
    ) -> list[dict]:
        pl_entry: dict = {"PrefixListId": pl_id}
        if desc:
            pl_entry["Description"] = desc
        return [{
            "IpProtocol": proto,
            "FromPort": from_port,
            "ToPort": to_port,
            "IpRanges": [],
            "Ipv6Ranges": [],
            "UserIdGroupPairs": [],
            "PrefixListIds": [pl_entry],
        }]

    def test_resolved_prefix_list(self):
        """Resolved prefix list shows bracket CIDRs."""
        client = MagicMock()
        paginator = MagicMock()
        paginator.paginate.return_value = [
            {"Entries": [{"Cidr": "10.0.0.0/8"}]},
        ]
        client.get_paginator.return_value = paginator

        result = summarize_rules(
            self._make_pl_permission(),
            ec2_client=client,
        )
        assert "pl:pl-abc123[10.0.0.0/8]" in result
        assert "tcp:443" in result

    def test_no_client_unresolved(self):
        """Without ec2_client, prefix list is unresolved."""
        result = summarize_rules(
            self._make_pl_permission(),
        )
        assert "pl:pl-abc123" in result
        assert "[" not in result

    def test_empty_entries_unresolved(self):
        """Empty prefix list entries produce unresolved tag."""
        client = MagicMock()
        paginator = MagicMock()
        paginator.paginate.return_value = [{"Entries": []}]
        client.get_paginator.return_value = paginator

        result = summarize_rules(
            self._make_pl_permission(),
            ec2_client=client,
        )
        assert "pl:pl-abc123" in result
        assert "[" not in result

    def test_with_description(self):
        """Description is appended in parens."""
        result = summarize_rules(
            self._make_pl_permission(desc="S3 prefix list"),
        )
        assert "(S3 prefix list)" in result

    def test_mixed_cidr_and_prefix_list(self):
        """Both CIDR and prefix list appear in sources."""
        permissions = [{
            "IpProtocol": "tcp",
            "FromPort": 443,
            "ToPort": 443,
            "IpRanges": [{"CidrIp": "10.0.0.0/8"}],
            "Ipv6Ranges": [],
            "UserIdGroupPairs": [],
            "PrefixListIds": [
                {"PrefixListId": "pl-xxx"},
            ],
        }]
        result = summarize_rules(permissions)
        assert "10.0.0.0/8" in result
        assert "pl:pl-xxx" in result


# --- _check_sg_allows with prefix lists ---


class TestCheckSgAllowsPrefixList:
    """Tests for prefix list handling in _check_sg_allows."""

    def test_prefix_list_cidr_match(self):
        """IP within prefix list bracket CIDRs matches."""
        rules_str = (
            "tcp:443 from pl:pl-abc[10.0.0.0/8,172.16.0.0/12]"
        )
        rules = _parse_sg_rules(rules_str)
        allowed, reason = _check_sg_allows(
            rules, 443, "tcp", "10.1.2.3",
        )
        assert allowed is True
        assert "prefix list match" in reason

    def test_prefix_list_no_match(self):
        """IP outside prefix list CIDRs does not match."""
        rules_str = "tcp:443 from pl:pl-abc[10.0.0.0/8]"
        rules = _parse_sg_rules(rules_str)
        allowed, _ = _check_sg_allows(
            rules, 443, "tcp", "192.168.1.1",
        )
        assert allowed is False

    def test_unresolved_prefix_list_skipped(self):
        """Unresolved prefix list (no brackets) is skipped."""
        rules_str = "tcp:443 from pl:pl-abc"
        rules = _parse_sg_rules(rules_str)
        allowed, _ = _check_sg_allows(
            rules, 443, "tcp", "10.0.0.1",
        )
        assert allowed is False


# --- _find_cidr_rules with prefix lists ---


class TestFindCidrRulesPrefixList:
    """Tests for prefix list CIDR extraction in _find_cidr_rules."""

    def test_extracts_prefix_list_cidrs(self):
        """CIDRs from bracket notation are extracted."""
        rules_str = (
            "tcp:443 from pl:pl-abc[10.0.0.0/8,172.16.0.0/12]"
        )
        cidrs = _find_cidr_rules(rules_str, 443, "tcp")
        assert "10.0.0.0/8" in cidrs
        assert "172.16.0.0/12" in cidrs

    def test_unresolved_prefix_list_no_cidrs(self):
        """Unresolved prefix list produces no CIDRs."""
        rules_str = "tcp:443 from pl:pl-abc"
        cidrs = _find_cidr_rules(rules_str, 443, "tcp")
        assert cidrs == []
