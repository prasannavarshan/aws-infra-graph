"""Tests for CodeCommit, CodePipeline, and CodeBuild collectors."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

from src.collector.codebuild import CodeBuildCollector
from src.collector.codecommit import CodeCommitCollector
from src.collector.codepipeline import CodePipelineCollector
from src.graph.model import NodeLabel, RelationshipType


def _make_session() -> MagicMock:
    return MagicMock()


# --- CodeCommit Tests ---


class TestCodeCommitCollector:
    """Tests for CodeCommit repository collection."""

    def test_happy_path(self):
        """Should collect repos with branches."""
        collector = CodeCommitCollector(
            session=_make_session(),
            account_id="123456789012",
            regions=["us-west-2"],
        )
        client = MagicMock()
        client.list_repositories.return_value = {
            "repositories": [
                {"repositoryName": "infra-network-prod"},
                {"repositoryName": "app-core-beta"},
            ],
        }
        client.batch_get_repositories.return_value = {
            "repositories": [
                {
                    "Arn": (
                        "arn:aws:codecommit:us-west-2"
                        ":123456789012:infra-network-prod"
                    ),
                    "repositoryName": "infra-network-prod",
                    "repositoryId": "repo-001",
                    "defaultBranch": "main",
                    "repositoryDescription": "Prod network",
                    "cloneUrlHttp": "https://...",
                },
                {
                    "Arn": (
                        "arn:aws:codecommit:us-west-2"
                        ":123456789012:app-core-beta"
                    ),
                    "repositoryName": "app-core-beta",
                    "repositoryId": "repo-002",
                    "defaultBranch": "main",
                },
            ],
        }
        client.list_branches.return_value = {
            "branches": ["main", "develop"],
        }

        with patch.object(
            collector, "client", return_value=client,
        ):
            nodes, edges = collector.collect_in_region(
                "us-west-2",
            )

        assert len(nodes) == 2
        assert nodes[0].label == NodeLabel.CODECOMMIT_REPO
        assert nodes[0].name == "infra-network-prod"
        assert nodes[0].properties["default_branch"] == "main"
        assert "main" in nodes[0].properties["branches"]

    def test_empty_repos(self):
        """Should handle no repos gracefully."""
        collector = CodeCommitCollector(
            session=_make_session(),
            account_id="111111111111",
            regions=["us-west-2"],
        )
        client = MagicMock()
        client.list_repositories.return_value = {
            "repositories": [],
        }

        with patch.object(
            collector, "client", return_value=client,
        ):
            nodes, edges = collector.collect_in_region(
                "us-west-2",
            )

        assert nodes == []
        assert edges == []

    def test_api_failure(self):
        """Should handle ClientError gracefully."""
        from botocore.exceptions import ClientError

        collector = CodeCommitCollector(
            session=_make_session(),
            account_id="111111111111",
            regions=["us-west-2"],
        )
        client = MagicMock()
        client.list_repositories.side_effect = ClientError(
            {"Error": {"Code": "AccessDenied", "Message": ""}},
            "ListRepositories",
        )

        with patch.object(
            collector, "client", return_value=client,
        ):
            nodes, edges = collector.collect_in_region(
                "us-west-2",
            )

        assert nodes == []
        assert edges == []


# --- CodePipeline Tests ---


class TestCodePipelineCollector:
    """Tests for CodePipeline collection."""

    def _mock_pipeline_detail(self) -> dict:
        return {
            "pipeline": {
                "name": "cacicd-infra-network-pipeline",
                "roleArn": (
                    "arn:aws:iam::123456789012"
                    ":role/pipeline-role"
                ),
                "stages": [
                    {
                        "name": "Source",
                        "actions": [{
                            "name": "SourceCodePull",
                            "actionTypeId": {
                                "provider": "CodeCommit",
                            },
                            "configuration": {
                                "RepositoryName": (
                                    "infra-network-prod"
                                ),
                                "BranchName": "main",
                            },
                        }],
                    },
                    {
                        "name": "Build",
                        "actions": [{
                            "name": "Build",
                            "actionTypeId": {
                                "provider": "CodeBuild",
                            },
                            "configuration": {
                                "ProjectName": (
                                    "infra-network-prod"
                                ),
                            },
                        }],
                    },
                    {
                        "name": "Deploy",
                        "actions": [{
                            "name": "DeployStack",
                            "actionTypeId": {
                                "provider": "CloudFormation",
                            },
                            "configuration": {
                                "StackName": (
                                    "cacicd-infra-network"
                                ),
                                "ActionMode": "CREATE_UPDATE",
                                "RoleArn": (
                                    "arn:aws:iam::"
                                    "029213826572:role/"
                                    "DeploymentRole"
                                ),
                            },
                        }],
                    },
                ],
            },
            "metadata": {
                "pipelineArn": (
                    "arn:aws:codepipeline:us-west-2"
                    ":123456789012"
                    ":cacicd-infra-network-pipeline"
                ),
            },
        }

    def test_happy_path(self):
        """Should collect pipeline with source, build, deploy edges."""
        collector = CodePipelineCollector(
            session=_make_session(),
            account_id="123456789012",
            regions=["us-west-2"],
        )
        client = MagicMock()
        client.list_pipelines.return_value = {
            "pipelines": [
                {"name": "cacicd-infra-network-pipeline"},
            ],
        }
        client.get_pipeline.return_value = (
            self._mock_pipeline_detail()
        )

        with patch.object(
            collector, "client", return_value=client,
        ):
            nodes, edges = collector.collect_in_region(
                "us-west-2",
            )

        assert len(nodes) == 1
        assert nodes[0].label == NodeLabel.CODEPIPELINE
        assert nodes[0].properties["stage_count"] == 3

        # SOURCE_FROM -> CodeCommit
        source_edges = [
            e for e in edges
            if e.relationship == RelationshipType.SOURCE_FROM
        ]
        assert len(source_edges) == 1
        assert "infra-network-prod" in source_edges[0].target_arn
        assert source_edges[0].properties["branch"] == "main"

        # BUILDS_WITH -> CodeBuild
        build_edges = [
            e for e in edges
            if e.relationship == RelationshipType.BUILDS_WITH
        ]
        assert len(build_edges) == 1
        assert "infra-network-prod" in build_edges[0].target_arn

        # DEPLOYS_TO -> CloudFormation (cross-account)
        deploy_edges = [
            e for e in edges
            if e.relationship == RelationshipType.DEPLOYS_TO
        ]
        assert len(deploy_edges) == 1
        assert "029213826572" in deploy_edges[0].target_arn
        assert (
            deploy_edges[0].properties["target_account"]
            == "029213826572"
        )

    def test_cross_account_deploy(self):
        """Should extract target account from RoleArn."""
        collector = CodePipelineCollector(
            session=_make_session(),
            account_id="123456789012",
            regions=["us-west-2"],
        )
        client = MagicMock()
        client.list_pipelines.return_value = {
            "pipelines": [{"name": "test-pipe"}],
        }
        client.get_pipeline.return_value = (
            self._mock_pipeline_detail()
        )

        with patch.object(
            collector, "client", return_value=client,
        ):
            _, edges = collector.collect_in_region("us-west-2")

        deploy = [
            e for e in edges
            if e.relationship == RelationshipType.DEPLOYS_TO
        ]
        assert len(deploy) == 1
        assert (
            deploy[0].properties["target_account"]
            == "029213826572"
        )

    def test_api_failure(self):
        """Should handle ListPipelines failure."""
        from botocore.exceptions import ClientError

        collector = CodePipelineCollector(
            session=_make_session(),
            account_id="111111111111",
            regions=["us-west-2"],
        )
        client = MagicMock()
        client.list_pipelines.side_effect = ClientError(
            {"Error": {"Code": "AccessDenied", "Message": ""}},
            "ListPipelines",
        )

        with patch.object(
            collector, "client", return_value=client,
        ):
            nodes, edges = collector.collect_in_region(
                "us-west-2",
            )

        assert nodes == []
        assert edges == []


# --- CodeBuild Tests ---


class TestCodeBuildCollector:
    """Tests for CodeBuild project collection."""

    def test_happy_path(self):
        """Should collect build projects with source links."""
        collector = CodeBuildCollector(
            session=_make_session(),
            account_id="123456789012",
            regions=["us-west-2"],
        )
        client = MagicMock()
        client.list_projects.return_value = {
            "projects": ["infra-network-prod"],
        }
        client.batch_get_projects.return_value = {
            "projects": [{
                "arn": (
                    "arn:aws:codebuild:us-west-2"
                    ":123456789012"
                    ":project/infra-network-prod"
                ),
                "name": "infra-network-prod",
                "source": {
                    "type": "CODECOMMIT",
                    "location": (
                        "arn:aws:codecommit:us-west-2"
                        ":123456789012"
                        ":infra-network-prod"
                    ),
                    "buildspec": "buildspec.yaml",
                },
                "environment": {
                    "computeType": "BUILD_GENERAL1_SMALL",
                    "image": "aws/codebuild/standard:7.0",
                },
                "serviceRole": (
                    "arn:aws:iam::123456789012"
                    ":role/codebuild-role"
                ),
            }],
        }

        with patch.object(
            collector, "client", return_value=client,
        ):
            nodes, edges = collector.collect_in_region(
                "us-west-2",
            )

        assert len(nodes) == 1
        assert nodes[0].label == NodeLabel.CODEBUILD_PROJECT
        assert nodes[0].properties["source_type"] == "CODECOMMIT"

        # SOURCE_FROM -> CodeCommit
        assert len(edges) == 1
        assert (
            edges[0].relationship
            == RelationshipType.SOURCE_FROM
        )
        assert "infra-network-prod" in edges[0].target_arn

    def test_empty_projects(self):
        """Should handle no projects gracefully."""
        collector = CodeBuildCollector(
            session=_make_session(),
            account_id="111111111111",
            regions=["us-west-2"],
        )
        client = MagicMock()
        client.list_projects.return_value = {"projects": []}

        with patch.object(
            collector, "client", return_value=client,
        ):
            nodes, edges = collector.collect_in_region(
                "us-west-2",
            )

        assert nodes == []
        assert edges == []

    def test_non_codecommit_source(self):
        """Should not create edge for non-CodeCommit sources."""
        collector = CodeBuildCollector(
            session=_make_session(),
            account_id="111111111111",
            regions=["us-west-2"],
        )
        client = MagicMock()
        client.list_projects.return_value = {
            "projects": ["my-project"],
        }
        client.batch_get_projects.return_value = {
            "projects": [{
                "arn": (
                    "arn:aws:codebuild:us-west-2"
                    ":111111111111:project/my-project"
                ),
                "name": "my-project",
                "source": {
                    "type": "GITHUB",
                    "location": "https://github.com/org/repo",
                },
                "environment": {
                    "computeType": "BUILD_GENERAL1_SMALL",
                    "image": "aws/codebuild/standard:7.0",
                },
                "serviceRole": "arn:aws:iam::111111111111:role/r",
            }],
        }

        with patch.object(
            collector, "client", return_value=client,
        ):
            nodes, edges = collector.collect_in_region(
                "us-west-2",
            )

        assert len(nodes) == 1
        assert edges == []  # No edge for GitHub source
