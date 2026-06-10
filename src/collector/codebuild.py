"""CodeBuild collector — build projects."""

from __future__ import annotations

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


class CodeBuildCollector(BaseCollector):
    """Collects CodeBuild projects with source and IAM info."""

    def collect_in_region(
        self, region: str,
    ) -> tuple[list[ResourceNode], list[ResourceEdge]]:
        """Collect CodeBuild projects in a single region."""
        nodes: list[ResourceNode] = []
        edges: list[ResourceEdge] = []

        try:
            client = self.client("codebuild", region)
            project_names = self._list_project_names(
                client,
            )
            if not project_names:
                return nodes, edges
            self._process_projects(
                client, project_names, region,
                nodes, edges,
            )
        except ClientError as e:
            logger.error(
                "codebuild_collection_failed",
                error_code=e.response["Error"]["Code"],
                account_id=self.account_id,
                region=region,
            )

        return nodes, edges

    def _list_project_names(
        self, client,  # noqa: ANN001
    ) -> list[str]:
        """List all project names using pagination."""
        names: list[str] = []
        next_token = ""
        while True:
            kwargs: dict = {}
            if next_token:
                kwargs["nextToken"] = next_token
            resp = client.list_projects(**kwargs)
            names.extend(resp.get("projects", []))
            next_token = resp.get("nextToken", "")
            if not next_token:
                break
        return names

    def _process_projects(
        self,
        client,  # noqa: ANN001
        project_names: list[str],
        region: str,
        nodes: list[ResourceNode],
        edges: list[ResourceEdge],
    ) -> None:
        """Batch-get project details (max 100 per call)."""
        for i in range(0, len(project_names), 100):
            batch = project_names[i : i + 100]
            try:
                resp = client.batch_get_projects(
                    names=batch,
                )
                for proj in resp.get("projects", []):
                    self._process_project(
                        proj, region, nodes, edges,
                    )
            except ClientError as e:
                logger.warning(
                    "codebuild_batch_get_failed",
                    error_code=e.response["Error"]["Code"],
                    batch_size=len(batch),
                )

    def _process_project(
        self,
        proj: dict,
        region: str,
        nodes: list[ResourceNode],
        edges: list[ResourceEdge],
    ) -> None:
        """Process a single CodeBuild project."""
        arn = proj["arn"]
        name = proj["name"]
        source = proj.get("source", {})
        env = proj.get("environment", {})

        nodes.append(ResourceNode(
            arn=arn,
            name=name,
            label=NodeLabel.CODEBUILD_PROJECT,
            account_id=self.account_id,
            region=region,
            properties={
                "source_type": source.get("type", ""),
                "source_location": source.get(
                    "location", "",
                ),
                "buildspec": source.get(
                    "buildspec", "",
                ),
                "compute_type": env.get(
                    "computeType", "",
                ),
                "image": env.get("image", ""),
                "service_role": proj.get(
                    "serviceRole", "",
                ),
            },
        ))

        # Link to source CodeCommit repo if applicable
        if source.get("type") == "CODECOMMIT":
            location = source.get("location", "")
            if location:
                edges.append(ResourceEdge(
                    source_arn=arn,
                    target_arn=location,
                    relationship=(
                        RelationshipType.SOURCE_FROM
                    ),
                ))
