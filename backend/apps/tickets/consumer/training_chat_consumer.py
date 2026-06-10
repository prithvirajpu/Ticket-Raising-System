import json
import asyncio
import logging

from channels.generic.websocket import AsyncWebsocketConsumer
from channels.db import database_sync_to_async

from apps.tickets.utils import (
    save_agent_message,
    save_ai_message,
    build_ai_history,
    get_ticket
)
from apps.tickets.services import get_ai_customer_reply,evaluate_agent_service

logger = logging.getLogger(__name__)


class TrainingChatConsumer(AsyncWebsocketConsumer):

    async def connect(self):
        self.ticket_id = self.scope["url_route"]["kwargs"]["ticket_id"]
        self.room_group_name = f"training_chat_{self.ticket_id}"

        await self.channel_layer.group_add(
            self.room_group_name,
            self.channel_name
        )

        await self.accept()

    async def disconnect(self, close_code):
        await self.channel_layer.group_discard(
            self.room_group_name,
            self.channel_name
        )

    async def receive(self, text_data):
        data = json.loads(text_data)

        logger.info("Training ws received: %s", data)

        if data.get("type") == "chat_message":
            await self.handle_chat_message(data)
        if data.get("type") == "resolve_ticket":
            await self.handle_resolve_ticket()

    async def handle_chat_message(self, data):
        message = data.get("message", "").strip()

        if not message:
            return

        user = self.scope["user"]

        ticket = await get_ticket(self.ticket_id)

        agent_chat = await save_agent_message(ticket, message)

        await self.channel_layer.group_send(
            self.room_group_name,
            {
                "type": "chat_message",
                "message": agent_chat.message,
                "sender_id": user.id,
                "sender_name": user.name,
                "created_at": agent_chat.created_at.isoformat(),
            }
        )

        asyncio.create_task(
            self.generate_ai_reply(ticket)
        )

    async def generate_ai_reply(self, ticket):

        await self.channel_layer.group_send(
            self.room_group_name,
            {
                "type": "typing_indicator",
                "is_typing": True,
            }
        )
        try:
            await asyncio.sleep(2)

            history = await build_ai_history(ticket)

            ai_reply = await database_sync_to_async(
                get_ai_customer_reply
            )(ticket, history)

            ai_chat = await save_ai_message(ticket, ai_reply)

            await self.channel_layer.group_send(
                self.room_group_name,
                {
                    "type": "typing_indicator",
                    "is_typing": False,
                }
            )

            await self.channel_layer.group_send(
                self.room_group_name,
                {
                    "type": "chat_message",
                    "message": ai_chat.message,
                    "sender_id": 0,
                    "sender_name": "AI Customer",
                    "created_at": ai_chat.created_at.isoformat(),
                }
            )

        except Exception:
            logger.exception("AI ERROR")

            # STOP TYPING ON ERROR TOO
            await self.channel_layer.group_send(
                self.room_group_name,
                {
                    "type": "typing_indicator",
                    "is_typing": False,
                }
            )

    async def chat_message(self, event):
        await self.send(
            text_data=json.dumps(
                {
                    "type": "chat_message",
                    "message": event["message"],
                    "sender_id": event["sender_id"],
                    "sender_name": event["sender_name"],
                    "created_at": event["created_at"],
                }
            )
        )

    async def typing_indicator(self, event):
        await self.send(
            text_data=json.dumps(
                {
                    "type": "typing_indicator",
                    "is_typing": event["is_typing"],
                }
            )
        )

    async def handle_resolve_ticket(self):
        ticket= await get_ticket(self.ticket_id)

        await database_sync_to_async(ticket.mark_resolved)()

        await self.channel_layer.group_send(
            self.room_group_name,{
                'type':'ticket_resolved',
                'message':'Ticket marked as resolved'
            }
        )
        asyncio.create_task(evaluate_agent_service(ticket.id))
    
    async def ticket_resolved(self, event):
        await self.send(
            text_data=json.dumps({
                "type": "ticket_resolved",
                "message": event["message"]
            })
        )
        
    async def evaluation_result(self, event):
        await self.send(
            text_data=json.dumps({
                "type": "evaluation_result",
                "score": event["score"],
                "passed": event["passed"],
                "feedback": event["feedback"],
            })
        )