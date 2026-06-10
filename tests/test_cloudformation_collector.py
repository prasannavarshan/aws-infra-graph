"""Tests for the CloudFormation collector."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

from src.collector.cloudformation import CloudFormationCollector
from src.graph.model import NodeLabel, RelationshipType

ACCOUNT_ID = "123456789012"
REGION = "us-east-1"


def _make_stack(
    name: str = "my-stack",
    status: str = "CREATE_COMPLETE",
    parent_id: str = "",
    role_arn: str = "",
) -> dict:
    """Build a minimal stack dict for testing."""
    stack = {
        "StackName": name,
        "StackId": (
            f"arn:aws:cloudformation:{REGION}:{ACCOUNT_ID}"
            f":stack/{name}/guid-123"
        ),
        "StackStatus": status,
        "CreationTime": "2024-01-01T00:00:00Z",
        "Parameters": [
            {"ParameterKey": "Env", "ParameterValue": "prod"},
        ],
        "Outputs": [
            {"OutputKey": "Url", "OutputValue": "https://example.com"},
        ],
        "DriftInformation": {
            "StackDriftStatus": "NOT_CHECKED",
        },
        "EnableTerminationProtection": True,
    }
    if parent_id:
        stack["ParentId"] = parent_id
    if role_arn:
        stack["RoleARN"] = role_arn
    return stack


def _make_resource(
    logical_id: str,
    resource_type: str,
    physical_id: str,
) -> dict:
    return {
        "LogicalResourceId": logical_id,
        "ResourceType": resource_type,
        "PhysicalResourceId": physical_id,
        "ResourceStatus": "CREATE_COMPLETE",
    }


def _mock_cfn_client(
    stacks: list[dict],
    resources: list[dict] | None = None,
) -> MagicMock:
    """Create a mock CFN client with paginator stubs."""
    client = MagicMock()

    # describe_stacks paginator
    desc_pag = MagicMock()
    desc_pag.paginate.return_value = [{"Stacks": stacks}]

    # list_stack_resources paginator
    res_pag = MagicMock()
    res_pag.paginate.return_value = [
        {"StackResourceSummaries": resources or []},
    ]

    def _get_paginator(name: str):
        if name == "describe_stacks":
            return desc_pag
        if name == "list_stack_resources":
            return res_pag
        raise ValueError(f"Unknown paginator: {name}")

    client.get_paginator = _get_paginator
    return client


class TestHappyPath:
    """Happy path: stack nodes, MANAGES edges, properties."""

    def test_creates_stack_node(self):
        stack = _make_stack()
        client = _mock_cfn_client([stack])

        collector = CloudFormationCollector(
            session=MagicMock(),
            account_id=ACCOUNT_ID,
            regions=[REGION],
        )
        with patch.object(
            collector, "client", return_value=client,
        ):
            nodes, _ = collector.collect()

        cfn_nodes = [
            n for n in nodes
            if n.label == NodeLabel.CLOUDFORMATION_STACK
        ]
        assert len(cfn_nodes) == 1
        assert cfn_nodes[0].name == "my-stack"
        assert cfn_nodes[0].account_id == ACCOUNT_ID
        assert cfn_nodes[0].region == REGION

    def test_stack_properties(self):
        stack = _make_stack()
        client = _mock_cfn_client([stack])

        collector = CloudFormationCollector(
            session=MagicMock(),
            account_id=ACCOUNT_ID,
            regions=[REGION],
        )
        with patch.object(
            collector, "client", return_value=client,
        ):
            nodes, _ = collector.collect()

        node = nodes[0]
        assert node.properties["status"] == "CREATE_COMPLETE"
        assert "Env=prod" in node.properties["parameters"]
        assert "Url=https://example.com" in node.properties["outputs"]
        assert node.properties["termination_protection"] is True
        assert node.properties["drift_status"] == "NOT_CHECKED"

    def test_manages_edge_for_lambda(self):
        stack = _make_stack()
        resources = [
            _make_resource(
                "MyFunc", "AWS::Lambda::Function", "my-func",
            ),
        ]
        client = _mock_cfn_client([stack], resources)

        collector = CloudFormationCollector(
            session=MagicMock(),
            account_id=ACCOUNT_ID,
            regions=[REGION],
        )
        with patch.object(
            collector, "client", return_value=client,
        ):
            _, edges = collector.collect()

        manages = [
            e for e in edges
            if e.relationship == RelationshipType.MANAGES
        ]
        assert len(manages) == 1
        assert manages[0].target_arn == (
            f"arn:aws:lambda:{REGION}:{ACCOUNT_ID}"
            f":function:my-func"
        )
        assert manages[0].properties["logical_id"] == "MyFunc"
        assert manages[0].properties["resource_type"] == (
            "AWS::Lambda::Function"
        )

    def test_nested_stack_part_of_edge(self):
        parent_arn = (
            f"arn:aws:cloudformation:{REGION}:{ACCOUNT_ID}"
            f":stack/parent/guid-parent"
        )
        stack = _make_stack(
            name="child-stack", parent_id=parent_arn,
        )
        client = _mock_cfn_client([stack])

        collector = CloudFormationCollector(
            session=MagicMock(),
            account_id=ACCOUNT_ID,
            regions=[REGION],
        )
        with patch.object(
            collector, "client", return_value=client,
        ):
            _, edges = collector.collect()

        part_of = [
            e for e in edges
            if e.relationship == RelationshipType.PART_OF
        ]
        assert len(part_of) == 1
        assert part_of[0].target_arn == parent_arn

    def test_has_role_edge(self):
        role_arn = f"arn:aws:iam::{ACCOUNT_ID}:role/CfnRole"
        stack = _make_stack(role_arn=role_arn)
        client = _mock_cfn_client([stack])

        collector = CloudFormationCollector(
            session=MagicMock(),
            account_id=ACCOUNT_ID,
            regions=[REGION],
        )
        with patch.object(
            collector, "client", return_value=client,
        ):
            _, edges = collector.collect()

        has_role = [
            e for e in edges
            if e.relationship == RelationshipType.HAS_ROLE
        ]
        assert len(has_role) == 1
        assert has_role[0].target_arn == role_arn


class TestEdgeCases:
    """Edge cases: filtering, unmapped types, empty regions."""

    def test_skip_delete_complete(self):
        stacks = [
            _make_stack(
                name="deleted", status="DELETE_COMPLETE",
            ),
            _make_stack(
                name="active", status="CREATE_COMPLETE",
            ),
        ]
        client = _mock_cfn_client(stacks)

        collector = CloudFormationCollector(
            session=MagicMock(),
            account_id=ACCOUNT_ID,
            regions=[REGION],
        )
        with patch.object(
            collector, "client", return_value=client,
        ):
            nodes, _ = collector.collect()

        names = [n.name for n in nodes]
        assert "deleted" not in names
        assert "active" in names

    def test_skip_delete_in_progress(self):
        stacks = [
            _make_stack(
                name="deleting", status="DELETE_IN_PROGRESS",
            ),
        ]
        client = _mock_cfn_client(stacks)

        collector = CloudFormationCollector(
            session=MagicMock(),
            account_id=ACCOUNT_ID,
            regions=[REGION],
        )
        with patch.object(
            collector, "client", return_value=client,
        ):
            nodes, _ = collector.collect()

        assert len(nodes) == 0

    def test_unmapped_resource_type_skipped(self):
        stack = _make_stack()
        resources = [
            _make_resource(
                "MyAlarm", "AWS::CloudWatch::Alarm",
                "my-alarm",
            ),
        ]
        client = _mock_cfn_client([stack], resources)

        collector = CloudFormationCollector(
            session=MagicMock(),
            account_id=ACCOUNT_ID,
            regions=[REGION],
        )
        with patch.object(
            collector, "client", return_value=client,
        ):
            _, edges = collector.collect()

        manages = [
            e for e in edges
            if e.relationship == RelationshipType.MANAGES
        ]
        assert len(manages) == 0

    def test_empty_region_returns_nothing(self):
        client = _mock_cfn_client([])

        collector = CloudFormationCollector(
            session=MagicMock(),
            account_id=ACCOUNT_ID,
            regions=[REGION],
        )
        with patch.object(
            collector, "client", return_value=client,
        ):
            nodes, edges = collector.collect()

        assert len(nodes) == 0
        assert len(edges) == 0


class TestErrorHandling:
    """Error handling: ClientError on describe/list."""

    def test_describe_stacks_client_error(self):
        """ClientError on describe_stacks → empty result."""
        from botocore.exceptions import ClientError

        client = MagicMock()
        pag = MagicMock()
        pag.paginate.side_effect = ClientError(
            {"Error": {"Code": "AccessDenied", "Message": "no"}},
            "DescribeStacks",
        )
        client.get_paginator.return_value = pag

        collector = CloudFormationCollector(
            session=MagicMock(),
            account_id=ACCOUNT_ID,
            regions=[REGION],
        )
        with patch.object(
            collector, "client", return_value=client,
        ):
            nodes, edges = collector.collect()

        assert len(nodes) == 0
        assert len(edges) == 0

    def test_list_resources_error_continues(self):
        """ClientError on list_stack_resources → stack node still created."""
        from botocore.exceptions import ClientError

        stack = _make_stack()
        client = MagicMock()

        # describe_stacks succeeds
        desc_pag = MagicMock()
        desc_pag.paginate.return_value = [{"Stacks": [stack]}]

        # list_stack_resources fails
        res_pag = MagicMock()
        res_pag.paginate.side_effect = ClientError(
            {
                "Error": {
                    "Code": "ValidationError",
                    "Message": "does not exist",
                },
            },
            "ListStackResources",
        )

        def _get_paginator(name: str):
            if name == "describe_stacks":
                return desc_pag
            if name == "list_stack_resources":
                return res_pag
            raise ValueError(f"Unknown: {name}")

        client.get_paginator = _get_paginator

        collector = CloudFormationCollector(
            session=MagicMock(),
            account_id=ACCOUNT_ID,
            regions=[REGION],
        )
        with patch.object(
            collector, "client", return_value=client,
        ):
            nodes, edges = collector.collect()

        # Stack node is still created
        assert len(nodes) == 1
        assert nodes[0].name == "my-stack"
        # No MANAGES edges (resource listing failed)
        manages = [
            e for e in edges
            if e.relationship == RelationshipType.MANAGES
        ]
        assert len(manages) == 0
