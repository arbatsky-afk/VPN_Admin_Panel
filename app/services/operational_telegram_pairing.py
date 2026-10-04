"""Bounded in-memory authorization policy for operational Telegram pairing."""

from __future__ import annotations

import re
import secrets
import time
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from enum import StrEnum

IDENTIFY_TTL_SECONDS = 300
IDENTIFY_MAX_FAILED_ATTEMPTS = 5
IDENTIFY_BACKOFF_SECONDS = (1, 2, 4, 8)
_IDENTIFY_ROUTE = re.compile(r"^/identify(?:\s|$)")
_IDENTIFY_CANDIDATE = re.compile(r"^/identify [0-9]{6}$")


class PairingDecisionKind(StrEnum):
    NOT_APPLICABLE = "not_applicable"
    ACCEPTED = "accepted"
    REJECTED = "rejected"
    THROTTLED = "throttled"
    INVALIDATED = "invalidated"
    EXPIRED = "expired"


@dataclass(frozen=True, slots=True)
class PairingChallenge:
    command: str
    generation: int
    ttl_seconds: int


@dataclass(frozen=True, slots=True)
class PairingDecision:
    kind: PairingDecisionKind
    failed_attempts: int = 0


@dataclass(slots=True)
class _PairingSession:
    chat_id: int
    command: str
    generation: int
    expires_at: float
    failed_attempts: int = 0
    failed_attempts_by_user: dict[int, int] = field(default_factory=dict)
    retry_after_by_user: dict[int, float] = field(default_factory=dict)


class OperationalTelegramPairing:
    """Evaluate pairing attempts without Telegram, Qt, persistence, or wall time."""

    def __init__(
        self,
        *,
        clock: Callable[[], float] = time.monotonic,
        code_factory: Callable[[], str] | None = None,
        ttl_seconds: int = IDENTIFY_TTL_SECONDS,
        max_failed_attempts: int = IDENTIFY_MAX_FAILED_ATTEMPTS,
        backoff_seconds: Sequence[int] = IDENTIFY_BACKOFF_SECONDS,
    ) -> None:
        if ttl_seconds <= 0:
            raise ValueError("Pairing TTL must be positive.")
        if max_failed_attempts <= 0:
            raise ValueError("Pairing attempt limit must be positive.")
        if not backoff_seconds or any(delay <= 0 for delay in backoff_seconds):
            raise ValueError("Pairing backoff delays must be positive.")
        self._clock = clock
        self._code_factory = code_factory or self._new_code
        self._ttl_seconds = ttl_seconds
        self._max_failed_attempts = max_failed_attempts
        self._backoff_seconds = tuple(backoff_seconds)
        self._generation = 0
        self._session: _PairingSession | None = None

    @property
    def active(self) -> bool:
        return self._session is not None

    def begin(self, chat_id: int) -> PairingChallenge:
        code = self._code_factory()
        if re.fullmatch(r"[0-9]{6}", code) is None:
            raise ValueError("Pairing code factory must return exactly six ASCII digits.")
        self._generation += 1
        command = f"/identify {code}"
        self._session = _PairingSession(
            chat_id=chat_id,
            command=command,
            generation=self._generation,
            expires_at=self._clock() + self._ttl_seconds,
        )
        return PairingChallenge(command, self._generation, self._ttl_seconds)

    def clear(self) -> None:
        self._session = None

    def expire(self, generation: int) -> bool:
        session = self._session
        if (
            session is None
            or session.generation != generation
            or self._clock() < session.expires_at
        ):
            return False
        self._session = None
        return True

    def evaluate(
        self,
        *,
        chat_id: int,
        user_id: int,
        text: str | None,
    ) -> PairingDecision:
        session = self._session
        if session is None:
            return PairingDecision(PairingDecisionKind.NOT_APPLICABLE)
        now = self._clock()
        if now >= session.expires_at:
            self._session = None
            return PairingDecision(PairingDecisionKind.EXPIRED)
        if chat_id != session.chat_id or text is None or _IDENTIFY_ROUTE.match(text) is None:
            return PairingDecision(PairingDecisionKind.NOT_APPLICABLE)
        if now < session.retry_after_by_user.get(user_id, 0.0):
            return PairingDecision(
                PairingDecisionKind.THROTTLED,
                session.failed_attempts,
            )
        if _IDENTIFY_CANDIDATE.fullmatch(text) is not None and secrets.compare_digest(
            text, session.command
        ):
            self._session = None
            return PairingDecision(
                PairingDecisionKind.ACCEPTED,
                session.failed_attempts,
            )

        session.failed_attempts += 1
        failed_attempts = session.failed_attempts
        if failed_attempts >= self._max_failed_attempts:
            self._session = None
            return PairingDecision(PairingDecisionKind.INVALIDATED, failed_attempts)
        user_failed_attempts = session.failed_attempts_by_user.get(user_id, 0) + 1
        session.failed_attempts_by_user[user_id] = user_failed_attempts
        delay_index = min(user_failed_attempts - 1, len(self._backoff_seconds) - 1)
        session.retry_after_by_user[user_id] = now + self._backoff_seconds[delay_index]
        return PairingDecision(PairingDecisionKind.REJECTED, failed_attempts)

    @staticmethod
    def _new_code() -> str:
        return f"{secrets.randbelow(1_000_000):06d}"
