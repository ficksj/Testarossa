from typing import Callable, Dict, Any, Awaitable
from aiogram import BaseMiddleware
from aiogram.types import Message, CallbackQuery
import config
from services.logger_service import get_logger

logger = get_logger("AuthMiddleware")

class AdminAuthMiddleware(BaseMiddleware):
    async def __call__(
        self,
        handler: Callable[[Message, Dict[str, Any]], Awaitable[Any]],
        event: Message | CallbackQuery,
        data: Dict[str, Any]
    ) -> Any:
        user = getattr(event, "from_user", None)
        chat = event.chat if isinstance(event, Message) else (event.message.chat if isinstance(event, CallbackQuery) and event.message else None)

        if chat is not None and getattr(chat, "type", None) != "private":
            logger.warning(f"Блокировка обращения из не-приватного чата (chat_id={chat.id}, type={chat.type})")
            return

        if not user or not config.ADMIN_IDS or user.id not in config.ADMIN_IDS:
            uid = getattr(user, "id", None)
            uname = getattr(user, "username", None)
            logger.warning(f"Несанкционированная попытка доступа от пользователя {uid} (@{uname})")
            if isinstance(event, Message):
                await event.answer("⛔ У вас нет прав для работы с этим ботом.")
            elif isinstance(event, CallbackQuery):
                await event.answer("⛔ Доступ запрещен.", show_alert=True)
            return

        return await handler(event, data)