"""Strict persisted settings for the Admin Panel operational Telegram bot."""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass

from .settings_manager import SettingsManager

TELEGRAM_OPERATIONS_SETTINGS_KEY = "telegram_operations"
TELEGRAM_OPERATIONS_SCHEMA_VERSION = 1
DEFAULT_AUDIT_LOG_RETENTION_DAYS = 30
MIN_AUDIT_LOG_RETENTION_DAYS = 1
MAX_AUDIT_LOG_RETENTION_DAYS = 3650
_BOT_TOKEN_RE = re.compile(r"^[1-9]\d{5,14}:[A-Za-z0-9_-]{20,}$")
_EXPECTED_KEYS = frozenset(
    {
        "schema_version",
        "bot_token",
        "chat_id",
        "authorized_user_id",
        "audit_log_retention_days",
    }
)


class OperationalTelegramSettingsError(ValueError):
    """The persisted operational Telegram section violates its schema."""


@dataclass(frozen=True, slots=True)
class OperationalTelegramSettings:
    """Validated schema-v1 settings used by the operational Telegram bot."""

    bot_token: str = ""
    chat_id: int | None = None
    authorized_user_id: int | None = None
    audit_log_retention_days: int = DEFAULT_AUDIT_LOG_RETENTION_DAYS

    @property
    def configured(self) -> bool:
        return bool(self.bot_token and self.chat_id is not None)

    @property
    def authorized(self) -> bool:
        return self.configured and self.authorized_user_id is not None

    def to_mapping(self) -> dict[str, object]:
        return {
            "schema_version": TELEGRAM_OPERATIONS_SCHEMA_VERSION,
            "bot_token": self.bot_token,
            "chat_id": self.chat_id,
            "authorized_user_id": self.authorized_user_id,
            "audit_log_retention_days": self.audit_log_retention_days,
        }

    @classmethod
    def from_mapping(cls, value: object) -> OperationalTelegramSettings:
        if not isinstance(value, Mapping) or set(value) != _EXPECTED_KEYS:
            raise OperationalTelegramSettingsError("Telegram settings have an invalid schema.")
        if value.get("schema_version") != TELEGRAM_OPERATIONS_SCHEMA_VERSION:
            raise OperationalTelegramSettingsError(
                "Telegram settings use an unsupported schema version."
            )
        return cls.validated(
            value.get("bot_token"),
            value.get("chat_id"),
            value.get("authorized_user_id"),
            value.get("audit_log_retention_days"),
        )

    @classmethod
    def validated(
        cls,
        bot_token: object,
        chat_id: object,
        authorized_user_id: object,
        audit_log_retention_days: object,
    ) -> OperationalTelegramSettings:
        if not isinstance(bot_token, str):
            raise OperationalTelegramSettingsError("Bot token must be text.")
        token = bot_token.strip()
        if token and not _BOT_TOKEN_RE.fullmatch(token):
            raise OperationalTelegramSettingsError("Bot token has an invalid format.")
        parsed_chat_id = _optional_nonzero_integer(chat_id, "Chat ID")
        parsed_user_id = _optional_nonzero_integer(authorized_user_id, "Authorized User ID")
        if bool(token) != (parsed_chat_id is not None):
            raise OperationalTelegramSettingsError(
                "Bot token and Chat ID must be filled in together."
            )
        if parsed_user_id is not None and not token:
            raise OperationalTelegramSettingsError(
                "Authorized User ID requires Bot token and Chat ID."
            )
        if (
            isinstance(audit_log_retention_days, bool)
            or not isinstance(audit_log_retention_days, int)
            or not MIN_AUDIT_LOG_RETENTION_DAYS
            <= audit_log_retention_days
            <= MAX_AUDIT_LOG_RETENTION_DAYS
        ):
            raise OperationalTelegramSettingsError(
                "Audit log retention must be between 1 and 3650 days."
            )
        return cls(token, parsed_chat_id, parsed_user_id, audit_log_retention_days)


def load_operational_telegram_settings(
    settings: SettingsManager,
) -> tuple[OperationalTelegramSettings, str | None]:
    """Load safely; an invalid section disables the bot without rewriting it."""
    raw = settings.get(TELEGRAM_OPERATIONS_SETTINGS_KEY)
    if raw is None:
        return OperationalTelegramSettings(), None
    try:
        return OperationalTelegramSettings.from_mapping(raw), None
    except OperationalTelegramSettingsError as error:
        return OperationalTelegramSettings(), str(error)


def save_operational_telegram_settings(
    settings: SettingsManager,
    value: OperationalTelegramSettings,
) -> None:
    settings.set(TELEGRAM_OPERATIONS_SETTINGS_KEY, value.to_mapping())
    settings.save()


def _optional_nonzero_integer(value: object, label: str) -> int | None:
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, int) or value == 0:
        raise OperationalTelegramSettingsError(f"{label} must be a non-zero integer.")
    return value
