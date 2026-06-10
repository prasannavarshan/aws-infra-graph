"""Tests for the connectivity analyzer tool."""

from __future__ import annotations

import pytest

from src.tools.connectivity import (
    _check_nacl_allows,
    _check_route_allows,
    _check_sg_allows,
    _check_tgw_route,
    _cidr_contains,
    _parse_nacl_rules,
    _parse_routes,
    _parse_sg_rules,
    _port_matches,
    _proto_matches,
)


class TestCidrContains:
    """Tests for CIDR matching utility."""

    def test_ip_in_cidr(self):
        assert _cidr_contains("10.0.0.0/8", "10.1.2.3") is True

    def test_ip_not_in_cidr(self):
        assert _cidr_contains("10.0.0.0/8", "172.16.0.1") is False

    def test_all_traffic_cidr(self):
        assert _cidr_contains("0.0.0.0/0", "192.168.1.1") is True

    def test_invalid_cidr_returns_false(self):
        assert _cidr_contains("not-a-cidr", "10.0.0.1") is False

    def test_invalid_ip_returns_false(self):
        assert _cidr_contains("10.0.0.0/8", "not-an-ip") is False


class TestPortMatches:
    """Tests for port matching."""

    def test_exact_port_match(self):
        assert _port_matches("443", 443) is True

    def test_exact_port_no_match(self):
        assert _port_matches("443", 80) is False

    def test_port_range_match(self):
        assert _port_matches("1024-65535", 8080) is True

    def test_port_range_no_match(self):
        assert _port_matches("1024-65535", 22) is False

    def test_all_ports(self):
        assert _port_matches("all", 443) is True


class TestProtoMatches:
    """Tests for protocol matching."""

    def test_exact_match(self):
        assert _proto_matches("tcp", "tcp") is True

    def test_all_matches_anything(self):
        assert _proto_matches("all", "tcp") is True

    def test_minus_one_matches_anything(self):
        assert _proto_matches("-1", "udp") is True

    def test_mismatch(self):
        assert _proto_matches("tcp", "udp") is False


class TestParseSGRules:
    """Tests for SG rule string parsing."""

    def test_parse_single_rule(self):
        rules = _parse_sg_rules("tcp:443 from 0.0.0.0/0")
        assert len(rules) == 1
        assert rules[0]["protocol"] == "tcp"
        assert rules[0]["port_str"] == "443"
        assert "0.0.0.0/0" in rules[0]["sources"]

    def test_parse_multiple_rules(self):
        rules = _parse_sg_rules(
            "tcp:443 from 0.0.0.0/0; tcp:80 from 10.0.0.0/8"
        )
        assert len(rules) == 2

    def test_parse_sg_reference(self):
        rules = _parse_sg_rules(
            "tcp:443 from sg:sg-abc123"
        )
        assert len(rules) == 1
        assert "sg:sg-abc123" in rules[0]["sources"]

    def test_parse_none_returns_empty(self):
        assert _parse_sg_rules("none") == []
        assert _parse_sg_rules("") == []

    def test_parse_with_description(self):
        rules = _parse_sg_rules(
            "tcp:443 from 0.0.0.0/0(Allow HTTPS)"
        )
        assert len(rules) == 1
        assert "0.0.0.0/0(Allow HTTPS)" in rules[0]["sources"]


class TestParseNACLRules:
    """Tests for NACL rule string parsing."""

    def test_parse_allow_rule(self):
        rules = _parse_nacl_rules(
            "Rule 100 ALLOW tcp:443 0.0.0.0/0"
        )
        assert len(rules) == 1
        assert rules[0]["rule_number"] == 100
        assert rules[0]["action"] == "ALLOW"
        assert rules[0]["protocol"] == "tcp"

    def test_parse_deny_rule(self):
        rules = _parse_nacl_rules(
            "Rule 200 DENY all:all 0.0.0.0/0"
        )
        assert len(rules) == 1
        assert rules[0]["action"] == "DENY"

    def test_parse_multiple(self):
        rules = _parse_nacl_rules(
            "Rule 100 ALLOW tcp:443 0.0.0.0/0; "
            "Rule 200 DENY all:all 10.0.0.0/8"
        )
        assert len(rules) == 2

    def test_parse_none_returns_empty(self):
        assert _parse_nacl_rules("none") == []


class TestCheckSGAllows:
    """Tests for SG rule evaluation."""

    def test_allows_matching_cidr(self):
        rules = _parse_sg_rules("tcp:443 from 0.0.0.0/0")
        allowed, _ = _check_sg_allows(
            rules, 443, "tcp", "10.0.0.1",
        )
        assert allowed is True

    def test_blocks_no_matching_rule(self):
        rules = _parse_sg_rules("tcp:80 from 0.0.0.0/0")
        allowed, reason = _check_sg_allows(
            rules, 443, "tcp", "10.0.0.1",
        )
        assert allowed is False
        assert "443" in reason

    def test_blocks_wrong_cidr(self):
        rules = _parse_sg_rules("tcp:443 from 10.0.0.0/8")
        allowed, _ = _check_sg_allows(
            rules, 443, "tcp", "172.16.0.1",
        )
        assert allowed is False

    def test_sg_reference_resolved_match(self):
        """SG-to-SG reference allows when remote has the referenced SG."""
        rules = _parse_sg_rules("tcp:443 from sg:sg-abc123")
        allowed, reason = _check_sg_allows(
            rules, 443, "tcp", "10.0.0.1",
            remote_sg_ids=frozenset({"sg-abc123"}),
        )
        assert allowed is True
        assert "SG match" in reason
        assert "sg:sg-abc123" in reason

    def test_sg_reference_no_match(self):
        """SG-to-SG reference denies when remote lacks the SG."""
        rules = _parse_sg_rules("tcp:443 from sg:sg-abc123")
        allowed, _ = _check_sg_allows(
            rules, 443, "tcp", "10.0.0.1",
            remote_sg_ids=frozenset({"sg-other"}),
        )
        assert allowed is False

    def test_sg_reference_no_remote_ids(self):
        """SG-to-SG reference denies when no remote SG IDs provided."""
        rules = _parse_sg_rules("tcp:443 from sg:sg-abc123")
        allowed, _ = _check_sg_allows(
            rules, 443, "tcp", "10.0.0.1",
        )
        assert allowed is False

    def test_allows_all_traffic_rule(self):
        rules = _parse_sg_rules("all:all from 0.0.0.0/0")
        allowed, _ = _check_sg_allows(
            rules, 8080, "tcp", "192.168.1.1",
        )
        assert allowed is True

    def test_allows_port_range(self):
        rules = _parse_sg_rules(
            "tcp:1024-65535 from 0.0.0.0/0",
        )
        allowed, _ = _check_sg_allows(
            rules, 8080, "tcp", "10.0.0.1",
        )
        assert allowed is True


class TestCheckNACLAllows:
    """Tests for NACL rule evaluation."""

    def test_allows_matching_rule(self):
        rules = _parse_nacl_rules(
            "Rule 100 ALLOW tcp:443 0.0.0.0/0"
        )
        allowed, _ = _check_nacl_allows(
            rules, 443, "tcp", "10.0.0.1",
        )
        assert allowed is True

    def test_deny_before_allow(self):
        """First matching rule wins — deny at 100 beats allow at 200."""
        rules = _parse_nacl_rules(
            "Rule 100 DENY tcp:443 0.0.0.0/0; "
            "Rule 200 ALLOW tcp:443 0.0.0.0/0"
        )
        allowed, reason = _check_nacl_allows(
            rules, 443, "tcp", "10.0.0.1",
        )
        assert allowed is False
        assert "Rule 100 DENY" in reason

    def test_implicit_deny_when_no_match(self):
        rules = _parse_nacl_rules(
            "Rule 100 ALLOW tcp:80 0.0.0.0/0"
        )
        allowed, reason = _check_nacl_allows(
            rules, 443, "tcp", "10.0.0.1",
        )
        assert allowed is False
        assert "implicit deny" in reason

    def test_cidr_scoped_allow(self):
        rules = _parse_nacl_rules(
            "Rule 100 ALLOW tcp:443 10.0.0.0/8"
        )
        allowed, _ = _check_nacl_allows(
            rules, 443, "tcp", "10.1.2.3",
        )
        assert allowed is True
        # IP outside range should be denied
        allowed_out, _ = _check_nacl_allows(
            rules, 443, "tcp", "172.16.0.1",
        )
        assert allowed_out is False

    def test_empty_rules_deny(self):
        allowed, _ = _check_nacl_allows(
            [], 443, "tcp", "10.0.0.1",
        )
        assert allowed is False


class TestParseRoutes:
    """Tests for route summary string parsing."""

    def test_parse_single_route(self):
        routes = _parse_routes("10.0.0.0/16 -> local")
        assert len(routes) == 1
        assert routes[0]["destination"] == "10.0.0.0/16"
        assert routes[0]["target"] == "local"

    def test_parse_multiple_routes(self):
        routes = _parse_routes(
            "10.0.0.0/16 -> local; 0.0.0.0/0 -> igw-abc123"
        )
        assert len(routes) == 2

    def test_parse_none_returns_empty(self):
        assert _parse_routes("none") == []
        assert _parse_routes("") == []

    def test_parse_tgw_route(self):
        routes = _parse_routes(
            "10.150.0.0/16 -> tgw-abc123"
        )
        assert len(routes) == 1
        assert routes[0]["target"] == "tgw-abc123"


class TestCheckRouteAllows:
    """Tests for route evaluation."""

    def test_local_route_matches(self):
        routes = _parse_routes("10.0.0.0/16 -> local")
        found, reason, tgw_id, is_local = _check_route_allows(
            routes, "10.0.1.5",
        )
        assert found is True
        assert "local" in reason
        assert tgw_id == ""
        assert is_local is True

    def test_default_route_matches(self):
        routes = _parse_routes(
            "10.0.0.0/16 -> local; 0.0.0.0/0 -> igw-abc"
        )
        found, reason, tgw_id, is_local = _check_route_allows(
            routes, "172.16.0.1",
        )
        assert found is True
        assert "igw-abc" in reason
        assert tgw_id == ""
        assert is_local is False

    def test_longest_prefix_match(self):
        routes = _parse_routes(
            "10.0.0.0/8 -> tgw-broad; "
            "10.0.1.0/24 -> tgw-specific; "
            "0.0.0.0/0 -> igw-default"
        )
        found, reason, tgw_id, is_local = _check_route_allows(
            routes, "10.0.1.5",
        )
        assert found is True
        assert "tgw-specific" in reason
        assert tgw_id == "tgw-specific"
        assert is_local is False

    def test_tgw_route_returns_tgw_id(self):
        """Route targeting a TGW should return its ID."""
        routes = _parse_routes(
            "10.150.0.0/16 -> tgw-0abc123"
        )
        found, reason, tgw_id, is_local = _check_route_allows(
            routes, "10.150.1.5",
        )
        assert found is True
        assert tgw_id == "tgw-0abc123"
        assert is_local is False

    def test_no_matching_route(self):
        routes = _parse_routes("10.0.0.0/16 -> local")
        found, reason, tgw_id, is_local = _check_route_allows(
            routes, "172.16.0.1",
        )
        assert found is False
        assert "no route" in reason
        assert tgw_id == ""
        assert is_local is False

    def test_empty_routes(self):
        found, reason, _, _ = _check_route_allows(
            [], "10.0.0.1",
        )
        assert found is False

    def test_no_target_ip(self):
        routes = _parse_routes("0.0.0.0/0 -> igw-abc")
        found, reason, _, _ = _check_route_allows(routes, "")
        assert found is False
        assert "no target IP" in reason


class TestCheckTGWRoute:
    """Tests for TGW route table evaluation."""

    @pytest.mark.asyncio
    async def test_tgw_route_found(self):
        """TGW route table with matching route returns True."""
        class MockNeo4j:
            async def query(self, q, params):  # noqa: ANN001
                return [{
                    "rt_id": "tgw-rtb-001",
                    "rt_name": "main-rt",
                    "routes": (
                        "10.150.0.0/16 -> tgw-attach-abc;"
                        " 10.160.0.0/16 -> tgw-attach-def"
                    ),
                }]

        found, lines = await _check_tgw_route(
            MockNeo4j(), "tgw-0abc", "10.150.1.5",
        )
        assert found is True
        assert any("TGW ROUTE EXISTS" in line for line in lines)

    @pytest.mark.asyncio
    async def test_tgw_no_matching_route(self):
        """TGW route table without matching route returns False."""
        class MockNeo4j:
            async def query(self, q, params):  # noqa: ANN001
                return [{
                    "rt_id": "tgw-rtb-001",
                    "rt_name": "main-rt",
                    "routes": "10.150.0.0/16 -> tgw-attach-abc",
                }]

        found, lines = await _check_tgw_route(
            MockNeo4j(), "tgw-0abc", "172.16.0.1",
        )
        assert found is False
        assert any("TGW NO ROUTE" in line for line in lines)

    @pytest.mark.asyncio
    async def test_tgw_no_route_tables(self):
        """TGW with no route tables returns False."""
        class MockNeo4j:
            async def query(self, q, params):  # noqa: ANN001
                return []

        found, lines = await _check_tgw_route(
            MockNeo4j(), "tgw-0abc", "10.0.0.1",
        )
        assert found is False
        assert any("no route tables found" in line for line in lines)
