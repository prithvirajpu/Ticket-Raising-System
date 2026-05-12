import json
from django.utils.timezone import now
from channels.generic.websocket import AsyncWebsocketConsumer
from apps.tickets.services import send_message_service
from channels.db import database_sync_to_async
import logging

logger = logging.getLogger(__name__)

class ChatConsumer(AsyncWebsocketConsumer):

    async def connect(self):
        self.ticket_id = self.scope['url_route']['kwargs']['ticket_id']
        self.room_group_name = f"chat_{self.ticket_id}"

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
        try:
            data = json.loads(text_data)
            message = data.get("message")
            user = self.scope["user"]

            logger.info("RECEIVE DATA: %s", data)
            logger.info("USER: %s", user)

            chat = await database_sync_to_async(send_message_service)(
                user=user,
                ticket_id=self.ticket_id,
                message=message
            )

            data = chat.get("data", {})

            await self.channel_layer.group_send(
                self.room_group_name,
                {
                    "type": "chat_message",
                    "message": data.get("message"),
                    "sender_id": data.get("sender_id"),
                    "sender_name": data.get("sender_name"),
                    "created_at": data.get("created_at"),
                }
            )

            logger.info("MESSAGE BROADCASTED")

        except Exception as e:
            logger.error("WS ERROR: %s", str(e))
            
    async def chat_message(self, event):
        logger.info("EVENT DATA: %s", event)
        await self.send(text_data=json.dumps({
            "message": event["message"],
            "sender_name": event["sender_name"],
            "sender_id": event["sender_id"],
            "created_at": event["created_at"],
        }))
