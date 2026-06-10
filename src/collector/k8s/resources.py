"""K8s resource collection — namespaces, nodes, workloads, services, SAs, ingresses."""

from __future__ import annotations

import re

import structlog

from src.collector.k8s.auth import ClusterConnection, k8s_api_get
from src.graph.model import (
    NodeLabel,
    RelationshipType,
    ResourceEdge,
    ResourceNode,
)

logger = structlog.get_logger()

# Regex to parse AWS providerID: aws:///az/instance-id
_PROVIDER_ID_RE = re.compile(
    r"aws:///[a-z0-9-]+/(i-[a-f0-9]+)",
)

# IRSA annotation key
_IRSA_ANNOTATION = "eks.amazonaws.com/role-arn"


def _k8s_arn(
    cluster_arn: str,
    kind: str,
    namespace: str,
    name: str,
) -> str:
    """Construct a synthetic ARN for a K8s resource.

    Format: arn:k8s:{cluster_arn}:{kind}/{namespace}/{name}

    Args:
        cluster_arn: Parent EKS cluster ARN.
        kind: K8s resource kind (e.g. 'namespace', 'node').
        namespace: K8s namespace (use '-' for cluster-scoped).
        name: Resource name.

    Returns:
        Synthetic ARN string.
    """
    return f"arn:k8s:{cluster_arn}:{kind}/{namespace}/{name}"


def _ec2_arn_from_provider_id(
    provider_id: str,
    account_id: str,
    region: str,
) -> str | None:
    """Parse providerID to extract EC2 instance ARN.

    Args:
        provider_id: K8s node spec.providerID like
            'aws:///us-east-1a/i-0abc123'.
        account_id: AWS account ID.
        region: AWS region.

    Returns:
        EC2 instance ARN or None if unparseable.
    """
    match = _PROVIDER_ID_RE.search(provider_id)
    if not match:
        return None
    instance_id = match.group(1)
    return (
        f"arn:aws:ec2:{region}:{account_id}"
        f":instance/{instance_id}"
    )


def collect_namespaces(
    conn: ClusterConnection,
) -> tuple[list[ResourceNode], list[ResourceEdge]]:
    """Collect K8s Namespace resources.

    Args:
        conn: ClusterConnection for the target cluster.

    Returns:
        Tuple of (nodes, edges). Each namespace gets a
        PART_OF edge to the parent EKSCluster.
    """
    data = k8s_api_get(conn, "/api/v1/namespaces")
    if not data:
        return [], []

    nodes: list[ResourceNode] = []
    edges: list[ResourceEdge] = []

    for item in data.get("items", []):
        meta = item.get("metadata", {})
        name = meta.get("name", "")
        arn = _k8s_arn(conn.cluster_arn, "namespace", "-", name)

        nodes.append(ResourceNode(
            arn=arn,
            name=name,
            label=NodeLabel.K8S_NAMESPACE,
            account_id=conn.account_id,
            region=conn.region,
            tags=meta.get("labels", {}),
            properties={
                "status": item.get("status", {}).get(
                    "phase", "",
                ),
                "cluster_name": conn.cluster_name,
            },
        ))
        edges.append(ResourceEdge(
            source_arn=arn,
            target_arn=conn.cluster_arn,
            relationship=RelationshipType.PART_OF,
        ))

    return nodes, edges


def collect_nodes(
    conn: ClusterConnection,
) -> tuple[list[ResourceNode], list[ResourceEdge]]:
    """Collect K8s Node resources with EC2 cross-boundary edges.

    Args:
        conn: ClusterConnection for the target cluster.

    Returns:
        Tuple of (nodes, edges). Includes PART_OF to
        EKSCluster and HOSTS_ON to EC2Instance.
    """
    data = k8s_api_get(conn, "/api/v1/nodes")
    if not data:
        return [], []

    nodes: list[ResourceNode] = []
    edges: list[ResourceEdge] = []

    for item in data.get("items", []):
        meta = item.get("metadata", {})
        spec = item.get("spec", {})
        status = item.get("status", {})
        name = meta.get("name", "")
        arn = _k8s_arn(
            conn.cluster_arn, "node", "-", name,
        )

        # Extract node info from status
        node_info = status.get("nodeInfo", {})
        addresses = {
            a["type"]: a["address"]
            for a in status.get("addresses", [])
        }

        nodes.append(ResourceNode(
            arn=arn,
            name=name,
            label=NodeLabel.K8S_NODE,
            account_id=conn.account_id,
            region=conn.region,
            tags=meta.get("labels", {}),
            properties={
                "cluster_name": conn.cluster_name,
                "instance_type": meta.get(
                    "labels", {},
                ).get("node.kubernetes.io/instance-type", ""),
                "kubelet_version": node_info.get(
                    "kubeletVersion", "",
                ),
                "os_image": node_info.get("osImage", ""),
                "internal_ip": addresses.get(
                    "InternalIP", "",
                ),
                "hostname": addresses.get("Hostname", ""),
                "provider_id": spec.get("providerID", ""),
                "unschedulable": spec.get(
                    "unschedulable", False,
                ),
            },
        ))

        # PART_OF → EKSCluster
        edges.append(ResourceEdge(
            source_arn=arn,
            target_arn=conn.cluster_arn,
            relationship=RelationshipType.PART_OF,
        ))

        # HOSTS_ON → EC2Instance (via providerID)
        provider_id = spec.get("providerID", "")
        ec2_arn = _ec2_arn_from_provider_id(
            provider_id, conn.account_id, conn.region,
        )
        if ec2_arn:
            edges.append(ResourceEdge(
                source_arn=arn,
                target_arn=ec2_arn,
                relationship=RelationshipType.HOSTS_ON,
            ))

    return nodes, edges


def collect_workloads(
    conn: ClusterConnection,
) -> tuple[
    list[ResourceNode],
    list[ResourceEdge],
    dict[str, dict[str, str]],
]:
    """Collect Deployments, StatefulSets, and DaemonSets.

    Args:
        conn: ClusterConnection for the target cluster.

    Returns:
        Tuple of (nodes, edges, deployment_selectors).
        deployment_selectors maps ARN → label selector dict
        for Service→Deployment matching.
    """
    nodes: list[ResourceNode] = []
    edges: list[ResourceEdge] = []
    selectors: dict[str, dict[str, str]] = {}

    endpoints = [
        ("/apis/apps/v1/deployments", "deployment"),
        ("/apis/apps/v1/statefulsets", "statefulset"),
        ("/apis/apps/v1/daemonsets", "daemonset"),
    ]

    for api_path, kind in endpoints:
        data = k8s_api_get(conn, api_path)
        if not data:
            continue

        for item in data.get("items", []):
            meta = item.get("metadata", {})
            spec = item.get("spec", {})
            ns = meta.get("namespace", "default")
            name = meta.get("name", "")
            arn = _k8s_arn(
                conn.cluster_arn, kind, ns, name,
            )

            replicas = spec.get("replicas", 0)
            ready = (
                item.get("status", {})
                .get("readyReplicas", 0)
            )

            nodes.append(ResourceNode(
                arn=arn,
                name=name,
                label=NodeLabel.K8S_DEPLOYMENT,
                account_id=conn.account_id,
                region=conn.region,
                tags=meta.get("labels", {}),
                properties={
                    "cluster_name": conn.cluster_name,
                    "namespace": ns,
                    "kind": kind,
                    "replicas": replicas or 0,
                    "ready_replicas": ready or 0,
                },
            ))

            # RUNS_IN_NAMESPACE
            ns_arn = _k8s_arn(
                conn.cluster_arn, "namespace", "-", ns,
            )
            edges.append(ResourceEdge(
                source_arn=arn,
                target_arn=ns_arn,
                relationship=RelationshipType.RUNS_IN_NAMESPACE,
            ))

            # Store selector labels for service matching
            match_labels = (
                spec.get("selector", {})
                .get("matchLabels", {})
            )
            if match_labels:
                selectors[arn] = dict(match_labels)

    return nodes, edges, selectors


def collect_services(
    conn: ClusterConnection,
    deployment_selectors: dict[str, dict[str, str]],
) -> tuple[list[ResourceNode], list[ResourceEdge]]:
    """Collect K8s Service resources.

    Args:
        conn: ClusterConnection for the target cluster.
        deployment_selectors: Mapping of deployment ARN →
            label selector for SELECTS edge matching.

    Returns:
        Tuple of (nodes, edges). Includes SELECTS edges
        to matching deployments.
    """
    data = k8s_api_get(conn, "/api/v1/services")
    if not data:
        return [], []

    nodes: list[ResourceNode] = []
    edges: list[ResourceEdge] = []

    for item in data.get("items", []):
        meta = item.get("metadata", {})
        spec = item.get("spec", {})
        ns = meta.get("namespace", "default")
        name = meta.get("name", "")
        arn = _k8s_arn(
            conn.cluster_arn, "service", ns, name,
        )

        svc_type = spec.get("type", "ClusterIP")
        status = item.get("status", {})
        lb_status = status.get("loadBalancer", {})
        ingress_list = lb_status.get("ingress", [])
        hostname = ""
        if ingress_list:
            hostname = ingress_list[0].get("hostname", "")

        ports = [
            f"{p.get('port')}/{p.get('protocol', 'TCP')}"
            for p in spec.get("ports", [])
        ]

        nodes.append(ResourceNode(
            arn=arn,
            name=name,
            label=NodeLabel.K8S_SERVICE,
            account_id=conn.account_id,
            region=conn.region,
            tags=meta.get("labels", {}),
            properties={
                "cluster_name": conn.cluster_name,
                "namespace": ns,
                "type": svc_type,
                "cluster_ip": spec.get("clusterIP", ""),
                "ports": ports,
                "external_hostname": hostname,
                "selector": spec.get("selector", {}),
            },
        ))

        # RUNS_IN_NAMESPACE
        ns_arn = _k8s_arn(
            conn.cluster_arn, "namespace", "-", ns,
        )
        edges.append(ResourceEdge(
            source_arn=arn,
            target_arn=ns_arn,
            relationship=RelationshipType.RUNS_IN_NAMESPACE,
        ))

        # SELECTS → K8sDeployment (match selector)
        svc_selector = spec.get("selector", {})
        if svc_selector:
            _match_service_to_deployments(
                arn, ns, svc_selector,
                deployment_selectors, conn, edges,
            )

    return nodes, edges


def _match_service_to_deployments(
    svc_arn: str,
    svc_ns: str,
    svc_selector: dict[str, str],
    deployment_selectors: dict[str, dict[str, str]],
    conn: ClusterConnection,
    edges: list[ResourceEdge],
) -> None:
    """Create SELECTS edges from service to matching deployments."""
    for dep_arn, dep_labels in deployment_selectors.items():
        # Deployment must be in same namespace
        parts = dep_arn.split("/")
        if len(parts) < 3:
            continue
        dep_ns = parts[-2]
        if dep_ns != svc_ns:
            continue
        # Service selector must be a subset of deployment labels
        if all(
            dep_labels.get(k) == v
            for k, v in svc_selector.items()
        ):
            edges.append(ResourceEdge(
                source_arn=svc_arn,
                target_arn=dep_arn,
                relationship=RelationshipType.SELECTS,
            ))


def collect_service_accounts(
    conn: ClusterConnection,
) -> tuple[list[ResourceNode], list[ResourceEdge]]:
    """Collect K8s ServiceAccount resources with IRSA edges.

    Args:
        conn: ClusterConnection for the target cluster.

    Returns:
        Tuple of (nodes, edges). Includes ASSUMES_IRSA
        edges to IAMRole for annotated service accounts.
    """
    data = k8s_api_get(conn, "/api/v1/serviceaccounts")
    if not data:
        return [], []

    nodes: list[ResourceNode] = []
    edges: list[ResourceEdge] = []

    for item in data.get("items", []):
        meta = item.get("metadata", {})
        ns = meta.get("namespace", "default")
        name = meta.get("name", "")
        arn = _k8s_arn(
            conn.cluster_arn, "serviceaccount", ns, name,
        )
        annotations = meta.get("annotations", {}) or {}
        irsa_role = annotations.get(_IRSA_ANNOTATION, "")

        nodes.append(ResourceNode(
            arn=arn,
            name=name,
            label=NodeLabel.K8S_SERVICE_ACCOUNT,
            account_id=conn.account_id,
            region=conn.region,
            tags=meta.get("labels", {}),
            properties={
                "cluster_name": conn.cluster_name,
                "namespace": ns,
                "irsa_role_arn": irsa_role,
            },
        ))

        # RUNS_IN_NAMESPACE
        ns_arn = _k8s_arn(
            conn.cluster_arn, "namespace", "-", ns,
        )
        edges.append(ResourceEdge(
            source_arn=arn,
            target_arn=ns_arn,
            relationship=RelationshipType.RUNS_IN_NAMESPACE,
        ))

        # ASSUMES_IRSA → IAMRole
        if irsa_role:
            edges.append(ResourceEdge(
                source_arn=arn,
                target_arn=irsa_role,
                relationship=RelationshipType.ASSUMES_IRSA,
            ))

    return nodes, edges


def collect_ingresses(
    conn: ClusterConnection,
) -> tuple[list[ResourceNode], list[ResourceEdge]]:
    """Collect K8s Ingress resources.

    Returns empty on 404 (networking.k8s.io not available).

    Args:
        conn: ClusterConnection for the target cluster.

    Returns:
        Tuple of (nodes, edges).
    """
    data = k8s_api_get(
        conn,
        "/apis/networking.k8s.io/v1/ingresses",
    )
    if not data:
        return [], []

    nodes: list[ResourceNode] = []
    edges: list[ResourceEdge] = []

    for item in data.get("items", []):
        meta = item.get("metadata", {})
        spec = item.get("spec", {})
        ns = meta.get("namespace", "default")
        name = meta.get("name", "")
        arn = _k8s_arn(
            conn.cluster_arn, "ingress", ns, name,
        )

        status = item.get("status", {})
        lb_status = status.get("loadBalancer", {})
        ingress_list = lb_status.get("ingress", [])
        hostname = ""
        if ingress_list:
            hostname = ingress_list[0].get("hostname", "")

        rules_summary = _summarize_ingress_rules(
            spec.get("rules", []),
        )

        nodes.append(ResourceNode(
            arn=arn,
            name=name,
            label=NodeLabel.K8S_INGRESS,
            account_id=conn.account_id,
            region=conn.region,
            tags=meta.get("labels", {}),
            properties={
                "cluster_name": conn.cluster_name,
                "namespace": ns,
                "ingress_class": spec.get(
                    "ingressClassName", "",
                ),
                "external_hostname": hostname,
                "rules": rules_summary,
            },
        ))

        # RUNS_IN_NAMESPACE
        ns_arn = _k8s_arn(
            conn.cluster_arn, "namespace", "-", ns,
        )
        edges.append(ResourceEdge(
            source_arn=arn,
            target_arn=ns_arn,
            relationship=RelationshipType.RUNS_IN_NAMESPACE,
        ))

    return nodes, edges


def _summarize_ingress_rules(
    rules: list[dict],
) -> list[str]:
    """Summarize ingress rules into human-readable strings."""
    summaries: list[str] = []
    for rule in rules:
        host = rule.get("host", "*")
        for path_entry in rule.get("http", {}).get(
            "paths", [],
        ):
            path = path_entry.get("path", "/")
            backend = path_entry.get("backend", {})
            svc = backend.get("service", {})
            svc_name = svc.get("name", "?")
            port = svc.get("port", {}).get(
                "number",
                svc.get("port", {}).get("name", "?"),
            )
            summaries.append(
                f"{host}{path} → {svc_name}:{port}",
            )
    return summaries
