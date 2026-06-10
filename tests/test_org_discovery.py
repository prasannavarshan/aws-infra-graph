"""Tests for Organization account auto-discovery."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from botocore.exceptions import ClientError

from src.collector.base import BaseCollector
from src.graph.builder import GraphBuilder, discover_org_accounts
from src.graph.model import NodeLabel, RelationshipType, ResourceEdge, ResourceNode


class FakeCollector(BaseCollector):
    """Test collector that returns fixed data."""

    def collect_in_region(self, region):
        node = ResourceNode(
            arn=f"arn:aws:test:{region}:{self.account_id}:fake/1",
            name="fake-resource",
            label=NodeLabel.VPC,
            account_id=self.account_id,
            region=region,
        )
        edge = ResourceEdge(
            source_arn=node.arn,
            target_arn=f"arn:aws:organizations::{self.account_id}:account",
            relationship=RelationshipType.BELONGS_TO,
        )
        return [node], [edge]


class TestDiscoverOrgAccounts:
    """Tests for discover_org_accounts()."""

    def test_happy_path_returns_active_accounts(self):
        """Returns only ACTIVE account IDs from Organizations."""
        mock_org = MagicMock()
        mock_paginator = MagicMock()
        mock_paginator.paginate.return_value = [
            {
                "Accounts": [
                    {"Id": "111111111111", "Status": "ACTIVE"},
                    {"Id": "222222222222", "Status": "ACTIVE"},
                    {"Id": "333333333333", "Status": "SUSPENDED"},
                ],
            },
        ]
        mock_org.get_paginator.return_value = mock_paginator

        mock_session = MagicMock()
        mock_session.client.return_value = mock_org

        with patch(
            "src.graph.builder.get_org_session",
            return_value=mock_session,
        ):
            result = discover_org_accounts()

        assert result == ["111111111111", "222222222222"]
        assert "333333333333" not in result

    def test_multi_page_pagination(self):
        """Handles multiple pages of accounts."""
        mock_org = MagicMock()
        mock_paginator = MagicMock()
        mock_paginator.paginate.return_value = [
            {
                "Accounts": [
                    {"Id": "111111111111", "Status": "ACTIVE"},
                ],
            },
            {
                "Accounts": [
                    {"Id": "222222222222", "Status": "ACTIVE"},
                ],
            },
        ]
        mock_org.get_paginator.return_value = mock_paginator

        mock_session = MagicMock()
        mock_session.client.return_value = mock_org

        with patch(
            "src.graph.builder.get_org_session",
            return_value=mock_session,
        ):
            result = discover_org_accounts()

        assert result == ["111111111111", "222222222222"]

    def test_api_error_propagates(self):
        """ClientError from Organizations API propagates to caller."""
        mock_org = MagicMock()
        mock_paginator = MagicMock()
        mock_paginator.paginate.side_effect = ClientError(
            {"Error": {"Code": "AccessDeniedException", "Message": "nope"}},
            "ListAccounts",
        )
        mock_org.get_paginator.return_value = mock_paginator

        mock_session = MagicMock()
        mock_session.client.return_value = mock_org

        with (
            patch(
                "src.graph.builder.get_org_session",
                return_value=mock_session,
            ),
            pytest.raises(ClientError),
        ):
            discover_org_accounts()


class TestBuildWithOrgDiscovery:
    """Tests for GraphBuilder.build() with org auto-discovery."""

    @pytest.mark.asyncio
    async def test_auto_discovers_when_role_set(self):
        """When cross_account_role_name is set, discovers from org."""
        mock_neo4j = AsyncMock()
        mock_neo4j.upsert_nodes = AsyncMock(return_value=1)
        mock_neo4j.upsert_edges = AsyncMock(return_value=1)

        with (
            patch("src.graph.builder.settings") as mock_settings,
            patch(
                "src.graph.builder.discover_org_accounts",
                return_value=["111111111111", "222222222222"],
            ) as mock_discover,
            patch(
                "src.graph.builder.get_current_account_id",
                return_value="000000000000",
            ),
            patch(
                "src.graph.builder.get_session_for_account",
            ) as mock_session,
        ):
            mock_settings.aws.account_ids = []
            mock_settings.aws.cross_account_role_name = "OrganizationAccessRole"
            mock_settings.aws.regions = ["us-east-1"]
            mock_settings.aws.max_concurrency = 5
            mock_settings.aws.collector_concurrency = 10
            mock_settings.neo4j.write_concurrency = 3
            mock_session.return_value = MagicMock()

            builder = GraphBuilder(
                neo4j=mock_neo4j,
                collector_classes=[FakeCollector],
            )
            result = await builder.build()

        mock_discover.assert_called_once()
        assert result["total_nodes"] == 2
        assert result["total_edges"] == 2

    @pytest.mark.asyncio
    async def test_falls_back_on_org_failure(self):
        """When org discovery fails, falls back to current account."""
        mock_neo4j = AsyncMock()
        mock_neo4j.upsert_nodes = AsyncMock(return_value=1)
        mock_neo4j.upsert_edges = AsyncMock(return_value=1)

        with (
            patch("src.graph.builder.settings") as mock_settings,
            patch(
                "src.graph.builder.discover_org_accounts",
                side_effect=ClientError(
                    {
                        "Error": {
                            "Code": "AccessDeniedException",
                            "Message": "no",
                        },
                    },
                    "ListAccounts",
                ),
            ),
            patch(
                "src.graph.builder.get_current_account_id",
                return_value="999888777666",
            ) as mock_detect,
            patch(
                "src.graph.builder.get_session_for_account",
            ) as mock_session,
        ):
            mock_settings.aws.account_ids = []
            mock_settings.aws.cross_account_role_name = "OrganizationAccessRole"
            mock_settings.aws.regions = ["us-east-1"]
            mock_settings.aws.max_concurrency = 5
            mock_settings.aws.collector_concurrency = 10
            mock_settings.neo4j.write_concurrency = 3
            mock_session.return_value = MagicMock()

            builder = GraphBuilder(
                neo4j=mock_neo4j,
                collector_classes=[FakeCollector],
            )
            result = await builder.build()

        mock_detect.assert_called()
        assert result["total_nodes"] == 1

    @pytest.mark.asyncio
    async def test_no_role_skips_org_discovery(self):
        """Without cross_account_role_name, skips org discovery."""
        mock_neo4j = AsyncMock()
        mock_neo4j.upsert_nodes = AsyncMock(return_value=1)
        mock_neo4j.upsert_edges = AsyncMock(return_value=1)

        with (
            patch("src.graph.builder.settings") as mock_settings,
            patch(
                "src.graph.builder.discover_org_accounts",
            ) as mock_discover,
            patch(
                "src.graph.builder.get_current_account_id",
                return_value="999888777666",
            ),
            patch(
                "src.graph.builder.get_session_for_account",
            ) as mock_session,
        ):
            mock_settings.aws.account_ids = []
            mock_settings.aws.cross_account_role_name = ""
            mock_settings.aws.regions = ["us-east-1"]
            mock_settings.aws.max_concurrency = 5
            mock_settings.aws.collector_concurrency = 10
            mock_settings.neo4j.write_concurrency = 3
            mock_session.return_value = MagicMock()

            builder = GraphBuilder(
                neo4j=mock_neo4j,
                collector_classes=[FakeCollector],
            )
            await builder.build()

        mock_discover.assert_not_called()
