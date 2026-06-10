"""CodeCommit collector — repositories and branches."""

from __future__ import annotations

import structlog
from botocore.exceptions import ClientError

from src.collector.base import BaseCollector
from src.graph.model import (
    NodeLabel,
    ResourceEdge,
    ResourceNode,
)

logger = structlog.get_logger()


class CodeCommitCollector(BaseCollector):
    """Collects CodeCommit repositories."""

    def collect_in_region(
        self, region: str,
    ) -> tuple[list[ResourceNode], list[ResourceEdge]]:
        """Collect CodeCommit repos in a single region."""
        nodes: list[ResourceNode] = []
        edges: list[ResourceEdge] = []

        try:
            client = self.client("codecommit", region)
            repo_names = self._list_repo_names(client)
            if not repo_names:
                return nodes, edges
            self._process_repos(
                client, repo_names, region, nodes,
            )
        except ClientError as e:
            logger.error(
                "codecommit_collection_failed",
                error_code=e.response["Error"]["Code"],
                account_id=self.account_id,
                region=region,
            )

        return nodes, edges

    def _list_repo_names(
        self, client,  # noqa: ANN001
    ) -> list[str]:
        """List all repository names using pagination."""
        names: list[str] = []
        next_token = ""
        while True:
            kwargs: dict = {}
            if next_token:
                kwargs["nextToken"] = next_token
            resp = client.list_repositories(**kwargs)
            for repo in resp.get("repositories", []):
                names.append(repo["repositoryName"])
            next_token = resp.get("nextToken", "")
            if not next_token:
                break
        return names

    def _process_repos(
        self,
        client,  # noqa: ANN001
        repo_names: list[str],
        region: str,
        nodes: list[ResourceNode],
    ) -> None:
        """Batch-get repository details."""
        # BatchGetRepositories accepts max 25 at a time
        for i in range(0, len(repo_names), 25):
            batch = repo_names[i : i + 25]
            try:
                resp = client.batch_get_repositories(
                    repositoryNames=batch,
                )
                for repo in resp.get("repositories", []):
                    self._process_repo(
                        client, repo, region, nodes,
                    )
            except ClientError as e:
                logger.warning(
                    "codecommit_batch_get_failed",
                    error_code=e.response["Error"]["Code"],
                    account_id=self.account_id,
                    batch_size=len(batch),
                )

    def _process_repo(
        self,
        client,  # noqa: ANN001
        repo: dict,
        region: str,
        nodes: list[ResourceNode],
    ) -> None:
        """Process a single repository."""
        arn = repo["Arn"]
        repo_name = repo["repositoryName"]

        branches = self._list_branches(client, repo_name)

        nodes.append(ResourceNode(
            arn=arn,
            name=repo_name,
            label=NodeLabel.CODECOMMIT_REPO,
            account_id=self.account_id,
            region=region,
            properties={
                "repository_id": repo.get(
                    "repositoryId", "",
                ),
                "clone_url_http": repo.get(
                    "cloneUrlHttp", "",
                ),
                "default_branch": repo.get(
                    "defaultBranch", "",
                ),
                "description": repo.get(
                    "repositoryDescription", "",
                ),
                "branches": branches,
            },
        ))

    def _list_branches(
        self,
        client,  # noqa: ANN001
        repo_name: str,
    ) -> list[str]:
        """List branch names for a repository."""
        branches: list[str] = []
        try:
            next_token = ""
            while True:
                kwargs: dict = {
                    "repositoryName": repo_name,
                }
                if next_token:
                    kwargs["nextToken"] = next_token
                resp = client.list_branches(**kwargs)
                branches.extend(
                    resp.get("branches", []),
                )
                next_token = resp.get("nextToken", "")
                if not next_token:
                    break
        except ClientError as e:
            logger.warning(
                "codecommit_list_branches_failed",
                repo=repo_name,
                error_code=e.response["Error"]["Code"],
            )
        return branches
