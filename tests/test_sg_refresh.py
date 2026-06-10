"""Tests for live SG refresh from AWS."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from botocore.exceptions import ClientError

from src.tools.sg_refresh import (
    _build_sg_result,
    _fetch_sgs_from_aws,
    refresh_security_groups,
)


def _make_aws_sg(
    group_id: str = "sg-abc123",
    group_name: str = "test-sg",
    vpc_id: str = "vpc-111",
    owner_id: str = "111111111111",
    ingress: list | None = None,
    egress: list | None = None,
    tags: list | None = None,
) -> dict:
    """Build a mock AWS describe_security_groups response SG."""
    return {
        "GroupId": group_id,
        "GroupName": group_name,
        "VpcId": vpc_id,
        "OwnerId": owner_id,
        "Description": "test sg",
        "IpPermissions": ingress or [],
        "IpPermissionsEgress": egress or [],
        "Tags": tags or [{"Key": "Name", "Value": group_name}],
    }


class TestBuildSgResult:
    """Tests for _build_sg_result helper."""

    def test_builds_dict_and_node(self):
        """Happy path: builds correct sg_dict and ResourceNode."""
        sg = _make_aws_sg(
            group_id="sg-111",
            group_name="my-sg",
            ingress=[{
                "IpProtocol": "tcp",
                "FromPort": 443,
                "ToPort": 443,
                "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
            }],
        )
        sg_dict, node = _build_sg_result(
            sg, "111111111111", "us-east-1",
        )

        assert sg_dict["group_id"] == "sg-111"
        assert sg_dict["name"] == "my-sg"
        assert sg_dict["vpc_id"] == "vpc-111"
        assert "tcp:443" in sg_dict["ingress"]
        assert node.label.value == "SecurityGroup"
        assert node.account_id == "111111111111"
        assert node.region == "us-east-1"
        assert node.properties["group_id"] == "sg-111"

    def test_no_tags_falls_back_to_group_name(self):
        """When no Name tag, uses GroupName."""
        sg = _make_aws_sg(tags=[])
        sg_dict, node = _build_sg_result(
            sg, "111111111111", "us-east-1",
        )
        assert sg_dict["name"] == "test-sg"


class TestRefreshSecurityGroups:
    """Tests for refresh_security_groups orchestrator."""

    @pytest.mark.asyncio
    async def test_refresh_single_account(self):
        """Happy path: 2 SGs in same account/region."""
        neo4j = AsyncMock()
        sg1 = _make_aws_sg(group_id="sg-aaa")
        sg2 = _make_aws_sg(group_id="sg-bbb")

        with patch(
            "src.tools.sg_refresh._fetch_sgs_from_aws",
            return_value=[sg1, sg2],
        ):
            result = await refresh_security_groups(
                neo4j,
                [
                    {
                        "group_id": "sg-aaa",
                        "account_id": "111",
                        "region": "us-east-1",
                    },
                    {
                        "group_id": "sg-bbb",
                        "account_id": "111",
                        "region": "us-east-1",
                    },
                ],
            )

        assert len(result) == 2
        assert result[0]["group_id"] == "sg-aaa"
        assert result[1]["group_id"] == "sg-bbb"
        neo4j.upsert_nodes.assert_awaited_once()
        upserted = neo4j.upsert_nodes.call_args[0][0]
        assert len(upserted) == 2

    @pytest.mark.asyncio
    async def test_refresh_cross_account(self):
        """SGs in different accounts trigger separate sessions."""
        neo4j = AsyncMock()
        sg1 = _make_aws_sg(group_id="sg-aaa")
        sg2 = _make_aws_sg(group_id="sg-bbb")

        call_count = 0

        def mock_fetch(account_id, region, group_ids):
            nonlocal call_count
            call_count += 1
            if account_id == "111":
                return [sg1]
            return [sg2]

        with patch(
            "src.tools.sg_refresh._fetch_sgs_from_aws",
            side_effect=mock_fetch,
        ):
            result = await refresh_security_groups(
                neo4j,
                [
                    {
                        "group_id": "sg-aaa",
                        "account_id": "111",
                        "region": "us-east-1",
                    },
                    {
                        "group_id": "sg-bbb",
                        "account_id": "222",
                        "region": "eu-west-1",
                    },
                ],
            )

        assert call_count == 2
        assert len(result) == 2
        gids = {sg["group_id"] for sg in result}
        assert gids == {"sg-aaa", "sg-bbb"}

    @pytest.mark.asyncio
    async def test_refresh_upserts_to_neo4j(self):
        """Verify neo4j.upsert_nodes called with ResourceNodes."""
        neo4j = AsyncMock()
        sg = _make_aws_sg(
            group_id="sg-111",
            ingress=[{
                "IpProtocol": "tcp",
                "FromPort": 6379,
                "ToPort": 6379,
                "IpRanges": [{"CidrIp": "10.0.0.0/8"}],
            }],
        )

        with patch(
            "src.tools.sg_refresh._fetch_sgs_from_aws",
            return_value=[sg],
        ):
            await refresh_security_groups(
                neo4j,
                [{
                    "group_id": "sg-111",
                    "account_id": "111",
                    "region": "us-east-1",
                }],
            )

        neo4j.upsert_nodes.assert_awaited_once()
        nodes = neo4j.upsert_nodes.call_args[0][0]
        assert len(nodes) == 1
        node = nodes[0]
        assert node.properties["group_id"] == "sg-111"
        assert "tcp:6379" in node.properties["ingress_rules"]
        assert "10.0.0.0/8" in node.properties["ingress_rules"]

    @pytest.mark.asyncio
    async def test_refresh_aws_error_handled(self):
        """ClientError for one group doesn't crash; partial ok."""
        neo4j = AsyncMock()
        sg_ok = _make_aws_sg(group_id="sg-ok")

        call_idx = 0

        def mock_fetch(account_id, region, group_ids):
            nonlocal call_idx
            call_idx += 1
            if account_id == "bad":
                raise ClientError(
                    {"Error": {"Code": "AccessDenied", "Message": "no"}},
                    "DescribeSecurityGroups",
                )
            return [sg_ok]

        with patch(
            "src.tools.sg_refresh._fetch_sgs_from_aws",
            side_effect=mock_fetch,
        ):
            result = await refresh_security_groups(
                neo4j,
                [
                    {
                        "group_id": "sg-ok",
                        "account_id": "good",
                        "region": "us-east-1",
                    },
                    {
                        "group_id": "sg-fail",
                        "account_id": "bad",
                        "region": "us-east-1",
                    },
                ],
            )

        # Only the successful SG is returned
        assert len(result) == 1
        assert result[0]["group_id"] == "sg-ok"

    @pytest.mark.asyncio
    async def test_refresh_empty_refs(self):
        """Empty sg_refs returns empty list, no upsert."""
        neo4j = AsyncMock()
        result = await refresh_security_groups(neo4j, [])
        assert result == []
        neo4j.upsert_nodes.assert_not_awaited()


class TestFetchSgsFromAws:
    """Tests for _fetch_sgs_from_aws."""

    def test_calls_describe_security_groups(self):
        """Verify boto3 call with correct GroupIds."""
        mock_session = MagicMock()
        mock_ec2 = MagicMock()
        mock_ec2.describe_security_groups.return_value = {
            "SecurityGroups": [_make_aws_sg()],
        }
        mock_session.client.return_value = mock_ec2

        with patch(
            "src.tools.sg_refresh.get_session_for_account",
            return_value=mock_session,
        ):
            result = _fetch_sgs_from_aws(
                "111", "us-east-1", ["sg-abc123"],
            )

        assert len(result) == 1
        mock_ec2.describe_security_groups.assert_called_once_with(
            GroupIds=["sg-abc123"],
        )
