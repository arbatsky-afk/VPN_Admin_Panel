"""Immutable public contracts for subscription publication."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Literal

SubscriptionRegistryState = Literal["pending", "active", "deleting"]
SubscriptionOutcome = Literal["success", "failure", "partial", "unknown"]
SubscriptionDeleteKind = Literal["orphan", "active"]
SubscriptionServerAvailability = Literal["ready", "letsencrypt_required"]
SubscriptionReconciliationStatus = Literal[
    "active",
    "missing",
    "orphan",
    "active_orphan",
    "missing_orphan",
    "deleting",
    "republish_required",
]


class SubscriptionError(ValueError):
    """A subscription request, local source, registry, or response is invalid."""


@dataclass(frozen=True, slots=True)
class SubscriptionSource:
    server_ip: str
    source_id: str
    path: Path
    uris: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class SubscriptionSourceFile:
    filename: str
    server_ip: str
    source_id: str
    name: str


@dataclass(frozen=True, slots=True)
class SubscriptionCandidate:
    name: str
    content: bytes
    content_sha256: str
    sources: tuple[SubscriptionSource, ...]


@dataclass(frozen=True, slots=True)
class SubscriptionRegistryEntry:
    server_ip: str
    name: str
    token: str
    state: SubscriptionRegistryState
    server_name: str | None
    created_at: str
    last_published_at: str | None
    content_sha256: str | None


@dataclass(frozen=True, slots=True)
class SubscriptionPublishRequest:
    operation_token: int
    request_id: int
    server_ip: str
    name: str
    token: str
    content_sha256: str
    content_size: int
    source_filenames: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class PreparedSubscription:
    request: SubscriptionPublishRequest
    content: bytes


@dataclass(frozen=True, slots=True)
class SubscriptionPublishResult:
    outcome: SubscriptionOutcome
    server_name: str = ""
    content_sha256: str = ""
    content_size: int = 0
    cleanup_failed_count: int = 0
    error: str = ""


@dataclass(frozen=True, slots=True)
class FinalizedSubscription:
    result: SubscriptionPublishResult
    url: str = ""


@dataclass(frozen=True, slots=True)
class SubscriptionServerArtifact:
    """One strict panel-owned subscription identity observed on a server."""

    name: str
    token: str


@dataclass(frozen=True, slots=True)
class SubscriptionServerSnapshot:
    """Validated managed-Nginx state and its observed subscription artifacts."""

    server_ip: str
    availability: SubscriptionServerAvailability
    server_name: str
    tls_mode: str
    artifacts: tuple[SubscriptionServerArtifact, ...]


@dataclass(frozen=True, slots=True)
class SubscriptionReconciliationItem:
    """One name-level projection of desired Registry and observed server state."""

    name: str
    status: SubscriptionReconciliationStatus
    registry_state: SubscriptionRegistryState | None
    desired_token: str | None
    matching_artifact: SubscriptionServerArtifact | None
    orphan_artifacts: tuple[SubscriptionServerArtifact, ...]


@dataclass(frozen=True, slots=True)
class SubscriptionReconciliation:
    """Current reconciled view for one immutable selected server."""

    server_ip: str
    availability: SubscriptionServerAvailability
    server_name: str
    items: tuple[SubscriptionReconciliationItem, ...]


@dataclass(frozen=True, slots=True)
class SubscriptionInspectRequest:
    """Immutable identity for one read-only server inspection."""

    operation_token: int
    request_id: int
    server_ip: str


@dataclass(frozen=True, slots=True)
class SubscriptionDeleteRequest:
    """Immutable exact-name deletion request derived from a reconciled view."""

    operation_token: int
    request_id: int
    server_ip: str
    kind: SubscriptionDeleteKind
    name: str
    tokens: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class SubscriptionDeleteResult:
    """Authoritative or uncertain outcome of one server deletion."""

    outcome: SubscriptionOutcome
    deleted_count: int = 0
    remaining_count: int = 0
    error: str = ""


@dataclass(frozen=True, slots=True)
class FinalizedSubscriptionDelete:
    """Deletion outcome plus a validated post-operation server snapshot."""

    result: SubscriptionDeleteResult
    snapshot: SubscriptionServerSnapshot | None = None
