from __future__ import annotations

import asyncio
import threading
from collections.abc import Awaitable, Callable, Sequence
from enum import StrEnum
from html import escape
from typing import Protocol, TypeVar, cast

from monitor.logs import JsonlLog

RECONNECT_BACKOFF_SECONDS = (5.0, 10.0, 30.0, 60.0, 120.0, 300.0)
REQUEST_TIMEOUT_SECONDS = 30.0
SHUTDOWN_TIMEOUT_SECONDS = 5.0
T = TypeVar("T")


class TelegramStatus(StrEnum):
    STARTING = "starting"
    ONLINE = "online"
    OFFLINE_RECONNECTING = "offline_reconnecting"


class TelegramClient(Protocol):
    async def connect(self) -> None: ...

    async def send(self, chat_id: int, message: str) -> None: ...

    async def poll(self, offset: int | None) -> tuple[int, ...]: ...

    async def close(self) -> None: ...


TelegramClientFactory = Callable[[str], TelegramClient]
TelegramStatusCallback = Callable[[TelegramStatus], None]


class TelegramDeliveryRejectedError(Exception):
    """A message-specific Telegram API rejection that reconnecting cannot fix."""

    def __init__(self, error_type: str) -> None:
        super().__init__(error_type)
        self.error_type = error_type


class AiogramTelegramClient:
    """Small aiogram adapter; incoming updates are drained and intentionally ignored."""

    def __init__(self, bot_token: str) -> None:
        from aiogram import Bot

        self._bot = Bot(bot_token)

    async def connect(self) -> None:
        await self._bot.get_me()
        await self._bot.delete_webhook(drop_pending_updates=True)

    async def send(self, chat_id: int, message: str) -> None:
        from aiogram.exceptions import TelegramBadRequest, TelegramForbiddenError

        try:
            await self._bot.send_message(
                chat_id=chat_id,
                text=f"<pre>{escape(message)}</pre>",
                parse_mode="HTML",
            )
        except (TelegramBadRequest, TelegramForbiddenError) as error:
            raise TelegramDeliveryRejectedError(type(error).__name__) from error

    async def poll(self, offset: int | None) -> tuple[int, ...]:
        updates = await self._bot.get_updates(
            offset=offset,
            timeout=20,
            allowed_updates=["message"],
        )
        return tuple(update.update_id for update in updates)

    async def close(self) -> None:
        await self._bot.session.close()


class _TransportFailureError(Exception):
    def __init__(self, phase: str, error: BaseException) -> None:
        super().__init__(phase)
        self.phase = phase
        self.error_type = type(error).__name__


class TelegramManager:
    def __init__(
        self,
        bot_token: object,
        chat_id: object,
        operation_log: JsonlLog,
        on_status: TelegramStatusCallback | None = None,
        client_factory: TelegramClientFactory | None = None,
        reconnect_delays: Sequence[float] = RECONNECT_BACKOFF_SECONDS,
        request_timeout_seconds: float = REQUEST_TIMEOUT_SECONDS,
    ) -> None:
        if not reconnect_delays or any(delay < 0 for delay in reconnect_delays):
            raise ValueError("Telegram reconnect delays must be non-negative.")
        if request_timeout_seconds <= 0:
            raise ValueError("Telegram request timeout must be positive.")
        self._bot_token = bot_token
        self._chat_id = chat_id
        self._operation_log = operation_log
        self._on_status = on_status or (lambda _status: None)
        self._client_factory = client_factory or AiogramTelegramClient
        self._reconnect_delays = tuple(float(delay) for delay in reconnect_delays)
        self._request_timeout_seconds = float(request_timeout_seconds)
        self._lock = threading.RLock()
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._loop: asyncio.AbstractEventLoop | None = None
        self._wake: asyncio.Event | None = None
        self._main_task: asyncio.Task[None] | None = None
        self._pending: tuple[int, str] | None = None
        self._sequence = 0
        self._status = TelegramStatus.OFFLINE_RECONNECTING

    @property
    def status(self) -> TelegramStatus:
        with self._lock:
            return self._status

    @property
    def running(self) -> bool:
        thread = self._thread
        return thread is not None and thread.is_alive()

    @property
    def pending_message(self) -> str | None:
        with self._lock:
            return self._pending[1] if self._pending is not None else None

    def start(self) -> None:
        with self._lock:
            if self.running:
                return
        configuration_error = self._configuration_error()
        if configuration_error is not None:
            self._operation_log.write(
                "telegram_configuration_error",
                reason=configuration_error,
            )
            self._set_status(TelegramStatus.OFFLINE_RECONNECTING)
            return
        self._stop.clear()
        self._set_status(TelegramStatus.STARTING)
        thread = threading.Thread(
            target=self._thread_main,
            name="monitor-telegram",
            daemon=False,
        )
        self._thread = thread
        thread.start()

    def submit(self, message: str) -> None:
        if not message:
            return
        with self._lock:
            self._sequence += 1
            self._pending = (self._sequence, message)
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
            return True
        thread.join(timeout)
        return not thread.is_alive()

    def _thread_main(self) -> None:
        try:
            asyncio.run(self._run())
        except BaseException as error:  # noqa: BLE001 - isolate the Monitor process
            if not self._stop.is_set():
                self._operation_log.write(
                    "telegram_internal_error",
                    error_type=type(error).__name__,
                )
        finally:
            with self._lock:
                self._loop = None
                self._wake = None
                self._main_task = None
            self._set_status(TelegramStatus.OFFLINE_RECONNECTING)

    async def _run(self) -> None:
        loop = asyncio.get_running_loop()
        wake = asyncio.Event()
        with self._lock:
            self._loop = loop
            self._wake = wake
            self._main_task = asyncio.current_task()
        delay_index = 0
        ever_online = False
        while not self._stop.is_set():
            client: TelegramClient | None = None
            failure: _TransportFailureError | None = None
            try:
                client = self._client_factory(cast(str, self._bot_token))
                await self._call(client.connect())
                delay_index = 0
                ever_online = True
                self._set_status(TelegramStatus.ONLINE)
                self._operation_log.write("telegram_online")
                await self._run_online(client)
            except asyncio.CancelledError:
                break
            except _TransportFailureError as error:
                failure = error
            except Exception as error:  # noqa: BLE001 - transport boundary
                failure = _TransportFailureError(
                    "reconnect" if ever_online else "connect",
                    error,
                )
            finally:
                if client is not None:
                    await self._close_client(client)
            if self._stop.is_set():
                break
            if failure is None:
                continue
            delay = self._reconnect_delays[min(delay_index, len(self._reconnect_delays) - 1)]
            delay_index += 1
            self._set_status(TelegramStatus.OFFLINE_RECONNECTING)
            self._operation_log.write(
                self._failure_event(failure.phase, ever_online),
                error_type=failure.error_type,
                retry_in_seconds=delay,
            )
            await self._wait_backoff(delay)

    async def _run_online(self, client: TelegramClient) -> None:
        offset: int | None = None
        while not self._stop.is_set():
            pending = self._pending_snapshot()
            if pending is not None:
                sequence, message = pending
                try:
                    await self._call(client.send(cast(int, self._chat_id), message))
                except asyncio.CancelledError:
                    raise
                except TelegramDeliveryRejectedError as error:
                    self._clear_pending(sequence)
                    self._operation_log.write(
                        "telegram_message_rejected",
                        error_type=error.error_type,
                    )
                    continue
                except Exception as error:  # noqa: BLE001 - transport boundary
                    raise _TransportFailureError("send", error) from error
                self._clear_pending(sequence)
                continue

            wake = self._wake
            if wake is None:
                return
            poll_task = asyncio.create_task(self._call(client.poll(offset)))
            wake_task = asyncio.create_task(wake.wait())
            tasks = {poll_task, wake_task}
            try:
                done, pending_tasks = await asyncio.wait(
                    tasks,
                    return_when=asyncio.FIRST_COMPLETED,
                )
            except BaseException:
                for task in tasks:
                    task.cancel()
                await asyncio.gather(*tasks, return_exceptions=True)
                raise
            for task in pending_tasks:
                task.cancel()
            await asyncio.gather(*pending_tasks, return_exceptions=True)
            if poll_task in done:
                try:
                    update_ids = poll_task.result()
                except asyncio.CancelledError:
                    raise
                except Exception as error:  # noqa: BLE001 - transport boundary
                    raise _TransportFailureError("poll", error) from error
                if update_ids:
                    offset = max(update_ids) + 1
            if wake_task in done:
                wake.clear()
                if self._stop.is_set():
                    return

    async def _wait_backoff(self, delay: float) -> None:
        loop = asyncio.get_running_loop()
        deadline = loop.time() + delay
        while not self._stop.is_set():
            remaining = deadline - loop.time()
            if remaining <= 0:
                return
            wake = self._wake
            if wake is None:
                return
            wake.clear()
            try:
                await asyncio.wait_for(wake.wait(), timeout=remaining)
            except TimeoutError:
                return

    async def _call(self, awaitable: Awaitable[T]) -> T:
        return await asyncio.wait_for(
            awaitable,
            timeout=self._request_timeout_seconds,
        )

    async def _close_client(self, client: TelegramClient) -> None:
        try:
            await asyncio.wait_for(client.close(), timeout=2.0)
        except asyncio.CancelledError:
            raise
        except Exception as error:  # noqa: BLE001 - shutdown boundary
            self._operation_log.write(
                "telegram_close_error",
                error_type=type(error).__name__,
            )

    def _pending_snapshot(self) -> tuple[int, str] | None:
        with self._lock:
            return self._pending

    def _clear_pending(self, sequence: int) -> None:
        with self._lock:
            if self._pending is not None and self._pending[0] == sequence:
                self._pending = None

    def _configuration_error(self) -> str | None:
        if not isinstance(self._bot_token, str) or not self._bot_token.strip():
            return "bot_token_missing"
        if self._bot_token != self._bot_token.strip():
            return "bot_token_invalid"
        if (
            isinstance(self._chat_id, bool)
            or not isinstance(self._chat_id, int)
            or self._chat_id == 0
        ):
            return "chat_id_missing_or_invalid"
        return None

    def _set_status(self, status: TelegramStatus) -> None:
        with self._lock:
            if self._status == status:
                return
            self._status = status
        try:
            self._on_status(status)
        except Exception as error:  # noqa: BLE001 - GUI callback isolation
            self._operation_log.write(
                "telegram_status_callback_error",
                error_type=type(error).__name__,
            )

    @staticmethod
    def _failure_event(phase: str, ever_online: bool) -> str:
        if phase == "send":
            return "telegram_send_error"
        if phase == "poll":
            return "telegram_connection_lost"
        return "telegram_reconnect_error" if ever_online else "telegram_connect_error"
