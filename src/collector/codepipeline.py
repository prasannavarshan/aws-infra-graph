"""CodePipeline collector — pipelines, stages, and deploy targets."""

from __future__ import annotations

import re

import structlog
from botocore.exceptions import ClientError

from src.collector.base import BaseCollector
from src.graph.model import (
    NodeLabel,
    RelationshipType,
    ResourceEdge,
    ResourceNode,
)

logger = structlog.get_logger()

# Pattern to extract account ID from cross-account role ARNs
_ACCOUNT_RE = re.compile(r"arn:aws:iam::(\d{12}):")


class CodePipelineCollector(BaseCollector):
    """Collects CodePipeline pipelines with source and deploy stages.

    Creates edges:
    - Pipeline -[SOURCE_FROM]-> CodeCommitRepo
    - Pipeline -[BUILDS_WITH]-> CodeBuildProject
    - Pipeline -[DEPLOYS_TO]-> CloudFormationStack (cross-account)
    """

    def collect_in_region(
        self, region: str,
    ) -> tuple[list[ResourceNode], list[ResourceEdge]]:
        """Collect pipelines in a single region."""
        nodes: list[ResourceNode] = []
        edges: list[ResourceEdge] = []

        try:
            client = self.client("codepipeline", region)
            pipe_names = self._list_pipeline_names(client)
            for name in pipe_names:
                self._process_pipeline(
                    client, name, region, nodes, edges,
                )
        except ClientError as e:
            logger.error(
                "codepipeline_collection_failed",
                error_code=e.response["Error"]["Code"],
                account_id=self.account_id,
                region=region,
            )

        return nodes, edges

    def _list_pipeline_names(
        self, client,  # noqa: ANN001
    ) -> list[str]:
        """List all pipeline names using pagination."""
        names: list[str] = []
        next_token = ""
        while True:
            kwargs: dict = {}
            if next_token:
                kwargs["nextToken"] = next_token
            resp = client.list_pipelines(**kwargs)
            for p in resp.get("pipelines", []):
                names.append(p["name"])
            next_token = resp.get("nextToken", "")
            if not next_token:
                break
        return names

    def _process_pipeline(
        self,
        client,  # noqa: ANN001
        name: str,
        region: str,
        nodes: list[ResourceNode],
        edges: list[ResourceEdge],
    ) -> None:
        """Get pipeline details and extract relationships."""
        try:
            resp = client.get_pipeline(name=name)
        except ClientError as e:
            logger.warning(
                "codepipeline_get_failed",
                pipeline=name,
                error_code=e.response["Error"]["Code"],
            )
            return

        pipeline = resp["pipeline"]
        metadata = resp.get("metadata", {})
        arn = metadata.get(
            "pipelineArn",
            f"arn:aws:codepipeline:{region}"
            f":{self.account_id}:{name}",
        )

        stages = pipeline.get("stages", [])
        stage_summary = self._summarize_stages(stages)

        nodes.append(ResourceNode(
            arn=arn,
            name=name,
            label=NodeLabel.CODEPIPELINE,
            account_id=self.account_id,
            region=region,
            properties={
                "stage_count": len(stages),
                "stages": stage_summary,
                "role_arn": pipeline.get("roleArn", ""),
            },
        ))

        # Extract relationships from stages
        self._extract_edges(
            arn, stages, region, edges,
        )

    def _summarize_stages(
        self, stages: list[dict],
    ) -> list[str]:
        """Return list of 'StageName:Provider' strings."""
        summary: list[str] = []
        for stage in stages:
            for action in stage.get("actions", []):
                provider = action["actionTypeId"]["provider"]
                summary.append(
                    f"{stage['name']}:{provider}",
                )
        return summary

    def _extract_edges(
        self,
        pipeline_arn: str,
        stages: list[dict],
        region: str,
        edges: list[ResourceEdge],
    ) -> None:
        """Extract source, build, and deploy edges."""
        for stage in stages:
            for action in stage.get("actions", []):
                provider = action["actionTypeId"]["provider"]
                cfg = action.get("configuration", {})

                if provider == "CodeCommit":
                    self._add_source_edge(
                        pipeline_arn, cfg, region, edges,
                    )
                elif provider == "CodeBuild":
                    self._add_build_edge(
                        pipeline_arn, cfg, region, edges,
                    )
                elif provider == "CloudFormation":
                    self._add_deploy_edge(
                        pipeline_arn, cfg, region, edges,
                    )

    def _add_source_edge(
        self,
        pipeline_arn: str,
        cfg: dict,
        region: str,
        edges: list[ResourceEdge],
    ) -> None:
        """Add SOURCE_FROM edge to CodeCommit repo."""
        repo_name = cfg.get("RepositoryName", "")
        branch = cfg.get("BranchName", "main")
        if not repo_name:
            return
        repo_arn = (
            f"arn:aws:codecommit:{region}"
            f":{self.account_id}:{repo_name}"
        )
        edges.append(ResourceEdge(
            source_arn=pipeline_arn,
            target_arn=repo_arn,
            relationship=RelationshipType.SOURCE_FROM,
            properties={"branch": branch},
        ))

    def _add_build_edge(
        self,
        pipeline_arn: str,
        cfg: dict,
        region: str,
        edges: list[ResourceEdge],
    ) -> None:
        """Add BUILDS_WITH edge to CodeBuild project."""
        project_name = cfg.get("ProjectName", "")
        if not project_name:
            return
        project_arn = (
            f"arn:aws:codebuild:{region}"
            f":{self.account_id}"
            f":project/{project_name}"
        )
        edges.append(ResourceEdge(
            source_arn=pipeline_arn,
            target_arn=project_arn,
            relationship=RelationshipType.BUILDS_WITH,
        ))

    def _add_deploy_edge(
        self,
        pipeline_arn: str,
        cfg: dict,
        region: str,
        edges: list[ResourceEdge],
    ) -> None:
        """Add DEPLOYS_TO edge to CloudFormation stack."""
        stack_name = cfg.get("StackName", "")
        if not stack_name:
            return

        # Extract target account from the RoleArn
        role_arn = cfg.get("RoleArn", "")
        match = _ACCOUNT_RE.match(role_arn)
        target_account = (
            match.group(1) if match else self.account_id
        )

        # Determine target region from stage name hints
        # or default to pipeline region
        target_region = region
        action_mode = cfg.get("ActionMode", "")

        stack_arn = (
            f"arn:aws:cloudformation:{target_region}"
            f":{target_account}:stack/{stack_name}/*"
        )
        edges.append(ResourceEdge(
            source_arn=pipeline_arn,
            target_arn=stack_arn,
            relationship=RelationshipType.DEPLOYS_TO,
            properties={
                "stack_name": stack_name,
                "target_account": target_account,
                "role_arn": role_arn,
                "action_mode": action_mode,
            },
        ))
