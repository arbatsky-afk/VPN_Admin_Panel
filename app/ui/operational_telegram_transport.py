"""Threaded aiogram transport for the Admin Panel operational Telegram bot."""

from __future__ import annotations

import asyncio
import threading
from collections import deque
from collections.abc import Awaitable, Callable, Sequence
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import StrEnum
from typing import Protocol, TypeVar

from app.services.operational_telegram_settings import OperationalTelegramSettings
from app.services.telegram_audit_log import TelegramAuditLog

RECONNECT_BACKOFF_SECONDS = (5.0, 10.0, 30.0, 60.0, 120.0, 300.0)
REQUEST_TIMEOUT_SECONDS = 30.0
SHUTDOWN_TIMEOUT_SECONDS = 5.0
T = TypeVar("T")


class OperationalTelegramStatus(StrEnum):
    DISABLED = "disabled"
    STARTING = "starting"
    PAIRING_REQUIRED = "pairing_required"
    ONLINE = "online"
    OFFLINE_RECONNECTING = "offline_reconnecting"


@dataclass(frozen=True, slots=True)
class TelegramButton:
    text: str
    callback_data: str


TelegramKeyboard = tuple[tuple[TelegramButton, ...], ...]


@dataclass(frozen=True, slots=True)
class OperationalTelegramUpdate:
    update_id: int
    chat_id: int
    user_id: int
    created_at: datetime
    message_id: int | None = None
    text: str | None = None
    callback_query_id: str | None = None
    callback_data: str | None = None


@dataclass(frozen=True, slots=True)
class TelegramOutbound:
    chat_id: int
    text: str = ""
    keyboard: TelegramKeyboard = ()
    message_id: int | None = None
    callback_query_id: str | None = None


class OperationalTelegramClient(Protocol):
    async def connect(self, chat_id: int) -> None: ...

    async def poll(self, offset: int | None) -> tuple[OperationalTelegramUpdate, ...]: ...

    async def deliver(self, outbound: TelegramOutbound) -> None: ...

    async def close(self) -> None: ...


ClientFactory = Callable[[str], OperationalTelegramClient]
StatusCallback = Callable[[OperationalTelegramStatus], None]
UpdateCallback = Callable[[OperationalTelegramUpdate], None]


class TelegramDeliveryRejectedError(Exception):
    """A message-specific Telegram API rejection that reconnecting cannot fix."""

    def __init__(self, error_type: str) -> None:
        super().__init__(error_type)
        self.error_type = error_type


class AiogramOperationalTelegramClient:
    """Narrow aiogram adapter with no operation or authorization logic."""

    def __init__(self, bot_token: str) -> None:
        from aiogram import Bot

        self._bot = Bot(bot_token)

    async def connect(self, chat_id: int) -> None:
        from aiogram.types import BotCommand, MenuButtonCommands

        await self._bot.get_me()
        await self._bot.set_my_commands(
            [
                BotCommand(command="start", description="Open operations menu"),
                BotCommand(command="menu", description="Return to main menu"),
            ]
        )
        await self._bot.set_chat_menu_button(
            chat_id=chat_id,
            menu_button=MenuButtonCommands(),
        )
        await self._bot.delete_webhook(drop_pending_updates=True)

    async def poll(self, offset: int | None) -> tuple[OperationalTelegramUpdate, ...]:
        updates = await self._bot.get_updates(
            offset=offset,
            timeout=20,
            allowed_updates=["message", "callback_query"],
        )
        parsed: list[OperationalTelegramUpdate] = []
        for update in updates:
            message = update.message
            if message is not None and message.from_user is not None:
                parsed.append(
                    OperationalTelegramUpdate(
                        update.update_id,
                        message.chat.id,
                        message.from_user.id,
                        message.date,
                        message_id=message.message_id,
                        text=message.text,
                    )
                )
                continue
            callback = update.callback_query
            callback_message = callback.message if callback is not None else None
            if (
                callback is not None
                and callback_message is not None
                and hasattr(callback_message, "chat")
            ):
                parsed.append(
                    OperationalTelegramUpdate(
                        update.update_id,
                        callback_message.chat.id,
                        callback.from_user.id,
                        datetime.now(timezone.utc),
                        message_id=callback_message.message_id,
                        callback_query_id=callback.id,
                        callback_data=callback.data,
                    )
                )
        return tuple(parsed)

    async def deliver(self, outbound: TelegramOutbound) -> None:
        from aiogram.exceptions import TelegramBadRequest, TelegramForbiddenError
        from aiogram.types import InlineKeyboardButton, InlineKeyboardMarkup

        try:
            if outbound.callback_query_id is not None:
                try:
                    await self._bot.answer_callback_query(outbound.callback_query_id)
                except TelegramBadRequest:
                    pass
                if not outbound.text:
                    return
            markup = None
            if outbound.keyboard:
                markup = InlineKeyboardMarkup(
                    inline_keyboard=[
                        [
                            InlineKeyboardButton(
                                text=button.text,
                                callback_data=button.callback_data,
                            )
                            for button in row
                        ]
                        for row in outbound.keyboard
                    ]
                )
            if outbound.message_id is not None:
                try:
                    await self._bot.edit_message_text(
                        chat_id=outbound.chat_id,
                        message_id=outbound.message_id,
                        text=outbound.text,
                        reply_markup=markup,
                    )
                    return
                except TelegramBadRequest:
                    pass
            await self._bot.send_message(
                chat_id=outbound.chat_id,
                text=outbound.text,
                reply_markup=markup,
            )
        except (TelegramBadRequest, TelegramForbiddenError) as error:
            raise TelegramDeliveryRejectedError(type(error).__name__) from error

    async def close(self) -> None:
        await self._bot.session.close()


class _TransportFailureError(Exception):
    def __init__(self, phase: str, error: BaseException) -> None:
        super().__init__(phase)
        self.phase = phase
        self.error_type = type(error).__name__


class OperationalTelegramManager:
    """Own an asyncio polling loop and bridge typed updates to the Qt process."""

    def __init__(
        self,
        settings: OperationalTelegramSettings,
        audit_log: TelegramAuditLog,
        on_status: StatusCallback,
        on_update: UpdateCallback,
        client_factory: ClientFactory | None = None,
        reconnect_delays: Sequence[float] = RECONNECT_BACKOFF_SECONDS,
        request_timeout_seconds: float = REQUEST_TIMEOUT_SECONDS,
    ) -> None:
        if not reconnect_delays or any(delay < 0 for delay in reconnect_delays):
            raise ValueError("Telegram reconnect delays must be non-negative.")
        if request_timeout_seconds <= 0:
            raise ValueError("Telegram request timeout must be positive.")
        self.settings = settings
        self._audit_log = audit_log
        self._on_status = on_status
        self._on_update = on_update
        self._client_factory = client_factory or AiogramOperationalTelegramClient
        self._reconnect_delays = tuple(float(value) for value in reconnect_delays)
        self._request_timeout_seconds = float(request_timeout_seconds)
        self._lock = threading.RLock()
        self._outbound: deque[TelegramOutbound] = deque()
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._loop: asyncio.AbstractEventLoop | None = None
        self._wake: asyncio.Event | None = None
        self._main_task: asyncio.Task[None] | None = None
        self._status = OperationalTelegramStatus.DISABLED

    @property
    def status(self) -> OperationalTelegramStatus:
        with self._lock:
            return self._status

    @property
    def running(self) -> bool:
        thread = self._thread
        return thread is not None and thread.is_alive()

    def start(self) -> None:
        with self._lock:
            if self.running:
                return
        if not self.settings.configured:
            self._set_status(OperationalTelegramStatus.DISABLED)
            return
        self._stop.clear()
        self._set_status(OperationalTelegramStatus.STARTING)
        self._thread = threading.Thread(
            target=self._thread_main,
            name="admin-panel-operational-telegram",
            daemon=False,
        )
        self._thread.start()

    def submit(self, outbound: TelegramOutbound) -> None:
        with self._lock:
            self._outbound.append(outbound)
            loop = self._loop
            wake = self._wake
        if loop is not None and wake is not None:
            try:
                loop.call_soon_threadsafe(wake.set)
            except RuntimeError:
                pass

    def stop(self, timeout: float = SHUTDOWN_TIMEOUT_SECONDS) -> bool:
        self._stop.set()
        with self._lock:
            loop = self._loop
            task = self._main_task
        if loop is not None and task is not None:
            try:
                loop.call_soon_threadsafe(task.cancel)
            except RuntimeError:
                pass
        thread = self._thread
        if thread is None:
            self._set_status(OperationalTelegramStatus.DISABLED)
            return True
        thread.join(timeout)
        stopped = not thread.is_alive()
        if stopped:
            self._set_status(OperationalTelegramStatus.DISABLED)
        return stopped

    def _thread_main(self) -> None:
        try:
            asyncio.run(self._run())
        except BaseException as error:  # noqa: BLE001 - isolate the desktop process
            if not self._stop.is_set():
                self._write_audit("transport_internal_error", error_type=type(error).__name__)
        finally:
            with self._lock:
                self._loop = None
                self._wake = None
                self._main_task = None
            if not self._stop.is_set():
                self._set_status(OperationalTelegramStatus.OFFLINE_RECONNECTING)

    async def _run(self) -> None:
        chat_id = self.settings.chat_id
        if chat_id is None:
            return
        loop = asyncio.get_running_loop()
        wake = asyncio.Event()
        with self._lock:
            self._loop = loop
            self._wake = wake
            self._main_task = asyncio.current_task()
        delay_index = 0
        ever_online = False
        while not self._stop.is_set():
            client: OperationalTelegramClient | None = None
            failure: _TransportFailureError | None = None
            try:
                client = self._client_factory(self.settings.bot_token)
                await self._call(client.connect(chat_id))
                delay_index = 0
                ever_online = True
                status = (
                    OperationalTelegramStatus.ONLINE
                    if self.settings.authorized
                    else OperationalTelegramStatus.PAIRING_REQUIRED
                )
                self._set_status(status)
                self._write_audit("transport_online", mode=status.value)
                await self._run_online(client)
            except asyncio.CancelledError:
                break
            except _TransportFailureError as error:
                failure = error
            except Exception as error:  # noqa: BLE001 - transport boundary
                failure = _TransportFailureError("reconnect" if ever_online else "connect", error)
            finally:
                if client is not None:
                    await self._close_client(client)
            if self._stop.is_set() or failure is None:
                continue
            delay = self._reconnect_delays[min(delay_index, len(self._reconnect_delays) - 1)]
            delay_index += 1
            self._set_status(OperationalTelegramStatus.OFFLINE_RECONNECTING)
            self._write_audit(
                "transport_offline",
                phase=failure.phase,
                error_type=failure.error_type,
                retry_in_seconds=delay,
            )
            await self._wait_backoff(delay)

    async def _run_online(self, client: OperationalTelegramClient) -> None:
        offset: int | None = None
        while not self._stop.is_set():
            outbound = self._outbound_snapshot()
            if outbound is not None:
                try:
                    await self._call(client.deliver(outbound))
                except asyncio.CancelledError:
                    raise
                except TelegramDeliveryRejectedError as error:
                    self._remove_outbound(outbound)
                    self._write_audit(
                        "outbound_rejected",
                        error_type=error.error_type,
                    )
                    continue
                except Exception as error:
                    raise _TransportFailureError("send", error) from error
                self._remove_outbound(outbound)
                continue
            wake = self._wake
            if wake is None:
                return
            poll_task = asyncio.create_task(self._call(client.poll(offset)))
            wake_task = asyncio.create_task(wake.wait())
            tasks = {poll_task, wake_task}
            try:
                done, pending = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
            except BaseException:
                for task in tasks:
                    task.cancel()
                await asyncio.gather(*tasks, return_exceptions=True)
                raise
            for task in pending:
                task.cancel()
            await asyncio.gather(*pending, return_exceptions=True)
            if poll_task in done:
                try:
                    updates = poll_task.result()
                except asyncio.CancelledError:
                    raise
                except Exception as error:
                    raise _TransportFailureError("poll", error) from error
                if updates:
                    offset = max(update.update_id for update in updates) + 1
                    for update in updates:
                        try:
                            self._on_update(update)
                        except Exception as error:  # noqa: BLE001 - callback isolation
                            self._write_audit(
                                "update_callback_error", error_type=type(error).__name__
                            )
            if wake_task in done:
                wake.clear()

    async def _call(self, awaitable: Awaitable[T]) -> T:
        return await asyncio.wait_for(awaitable, timeout=self._request_timeout_seconds)

    async def _close_client(self, client: OperationalTelegramClient) -> None:
        try:
            await asyncio.wait_for(client.close(), timeout=2.0)
        except asyncio.CancelledError:
            raise
        except Exception as error:  # noqa: BLE001 - shutdown boundary
            self._write_audit("transport_close_error", error_type=type(error).__name__)

    async def _wait_backoff(self, delay: float) -> None:
        wake = self._wake
        if wake is None:
            return
        wake.clear()
        try:
            await asyncio.wait_for(wake.wait(), timeout=delay)
        except TimeoutError:
            pass

    def _outbound_snapshot(self) -> TelegramOutbound | None:
        with self._lock:
            return self._outbound[0] if self._outbound else None

    def _remove_outbound(self, outbound: TelegramOutbound) -> None:
        with self._lock:
            if self._outbound and self._outbound[0] is outbound:
                self._outbound.popleft()

    def _set_status(self, status: OperationalTelegramStatus) -> None:
        with self._lock:
            if self._status == status:
                return
            self._status = status
        try:
            self._on_status(status)
        except Exception as error:  # noqa: BLE001 - GUI callback isolation
            self._write_audit("status_callback_error", error_type=type(error).__name__)

    def _write_audit(self, event: str, **fields: object) -> None:
        try:
            self._audit_log.write(event, **fields)
        except OSError:
            pass
