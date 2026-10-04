"""Deterministic reconciliation of desired Registry and observed server state."""

from __future__ import annotations

from collections import defaultdict
from pathlib import Path

from .contracts import (
    SubscriptionError,
    SubscriptionReconciliation,
    SubscriptionReconciliationItem,
    SubscriptionRegistryEntry,
    SubscriptionServerArtifact,
    SubscriptionServerSnapshot,
)
from .registry import SubscriptionRegistry


def reconcile_subscription_state(
    registry_entries: tuple[SubscriptionRegistryEntry, ...],
    snapshot: SubscriptionServerSnapshot,
) -> SubscriptionReconciliation:
    """Return a pure name-level projection for one exact server snapshot."""
    if any(entry.server_ip != snapshot.server_ip for entry in registry_entries):
        raise SubscriptionError("Subscription Registry entries do not match the server snapshot.")
    identities = [(entry.server_ip, entry.name) for entry in registry_entries]
    if len(identities) != len(set(identities)):
        raise SubscriptionError("Subscription Registry contains duplicate desired names.")
    artifact_identities = [(artifact.name, artifact.token) for artifact in snapshot.artifacts]
    if len(artifact_identities) != len(set(artifact_identities)):
        raise SubscriptionError("Subscription server snapshot contains duplicate artifacts.")
    if snapshot.availability != "ready":
        if snapshot.artifacts:
            raise SubscriptionError("Unavailable subscription server snapshot contains artifacts.")
        return SubscriptionReconciliation(
            snapshot.server_ip,
            snapshot.availability,
            snapshot.server_name,
            (),
        )

    desired_by_name = {entry.name: entry for entry in registry_entries}
    artifacts_by_name: dict[str, list[SubscriptionServerArtifact]] = defaultdict(list)
    for artifact in snapshot.artifacts:
        artifacts_by_name[artifact.name].append(artifact)

    items: list[SubscriptionReconciliationItem] = []
    for name in sorted(
        set(desired_by_name) | set(artifacts_by_name),
        key=lambda value: (value.casefold(), value),
    ):
        desired = desired_by_name.get(name)
        artifacts = tuple(sorted(artifacts_by_name.get(name, ()), key=lambda item: item.token))
        if desired is None:
            items.append(
                SubscriptionReconciliationItem(
                    name,
                    "orphan",
                    None,
                    None,
                    None,
                    artifacts,
                )
            )
            continue
        matching = next(
            (artifact for artifact in artifacts if artifact.token == desired.token),
            None,
        )
        orphan_artifacts = tuple(
            artifact for artifact in artifacts if artifact.token != desired.token
        )
        if desired.state == "deleting":
            status = "deleting"
        elif (
            matching is not None
            and desired.server_name is not None
            and desired.server_name != snapshot.server_name
        ):
            status = "republish_required"
        elif matching is not None and orphan_artifacts:
            status = "active_orphan"
        elif matching is not None:
            status = "active"
        elif orphan_artifacts:
            status = "missing_orphan"
        else:
            status = "missing"
        items.append(
            SubscriptionReconciliationItem(
                name,
                status,
                desired.state,
                desired.token,
                matching,
                orphan_artifacts,
            )
        )
    return SubscriptionReconciliation(
        snapshot.server_ip,
        snapshot.availability,
        snapshot.server_name,
        tuple(items),
    )


def reconcile_subscription_server(
    project_directory: Path,
    snapshot: SubscriptionServerSnapshot,
) -> SubscriptionReconciliation:
    """Finalize confirmed delete intents, then reconcile the current Registry."""
    registry = SubscriptionRegistry(project_directory)
    entries = registry.entries(snapshot.server_ip)
    if snapshot.availability == "ready":
        names_on_server = {artifact.name for artifact in snapshot.artifacts}
        for entry in entries:
            if entry.state == "deleting" and entry.name not in names_on_server:
                registry.complete_deletion(entry.server_ip, entry.name, entry.token)
        entries = registry.entries(snapshot.server_ip)
    return reconcile_subscription_state(entries, snapshot)
