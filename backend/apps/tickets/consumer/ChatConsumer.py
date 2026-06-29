import json
from django.utils.timezone import now
from channels.generic.websocket import AsyncWebsocketConsumer
from apps.tickets.services import send_message_service
from channels.db import database_sync_to_async
from apps.tickets.services import  mark_messages_read_service,mark_chat_notifications_read
import logging
import time

logger = logging.getLogger(__name__)

class ChatConsumer(AsyncWebsocketConsumer):

    async def connect(self):
        self.ticket_id = self.scope['url_route']['kwargs']['ticket_id']
        self.room_group_name = f"chat_{self.ticket_id}"
        self.user_room = f"user_{self.scope['user'].id}"
        logger.info('group for chat %s, group for call %s',self.room_group_name,self.user_room)

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
            event_type=data.get('type')

            logger.info("WS: event %s", event_type)
            if event_type=='chat_message':
                await self.handle_chat_message(data)
            elif event_type == "mark_read":
                logger.info('mard read received')
                await self.handle_mark_read(data)
            else:
                logger.warning('unknown event type: %s',event_type)

        except Exception as e:
            logger.error("WS ERROR: %s", str(e))

    async def handle_chat_message(self, data):
        message = data.get("message")
        user = self.scope["user"]

        start = time.perf_counter()

        chat = await database_sync_to_async(send_message_service)(
            user=user,
            ticket_id=self.ticket_id,
            message=message
        )

        logger.info(
            "send_message_service took %.3f seconds",
            time.perf_counter() - start
        )

        chat_data = chat.get("data", {})

        start = time.perf_counter()

        await self.channel_layer.group_send(
            self.room_group_name,
            {
                "type": "chat_message",
                "id": chat_data.get("id"),
                "message": chat_data.get("message"),
                "sender_id": chat_data.get("sender_id"),
                "sender_name": chat_data.get("sender_name"),
                "created_at": chat_data.get("created_at"),
            }
        )

        logger.info(
            "group_send took %.3f seconds",
            time.perf_counter() - start
        )

    async def chat_message(self, event):
        logger.info("EVENT DATA: %s", event)
        await self.send(text_data=json.dumps({
            'type':'chat_message',
            'id':event["id"],
            "message": event["message"],
            "sender_name": event["sender_name"],
            "sender_id": event["sender_id"],
            "created_at": event["created_at"],
        }))
    
    @database_sync_to_async
    def mark_read_db(self):
        return mark_messages_read_service(
            ticket_id=self.ticket_id,
            user=self.scope['user']
        )
    
    async def handle_mark_read(self, data):
        message_ids = await self.mark_read_db()
        logger.info("HANDLE MARK READ CALLED")
        logger.info('ids are ---%s',message_ids)

        await self.channel_layer.group_send(
            self.room_group_name,
            {
                "type": "messages_read",
                "message_ids": message_ids,
                "reader_id": self.scope["user"].id,
            }
        )

    async def messages_read(self, event):
        await self.send(
            text_data=json.dumps({
                "type": "messages_read",
                "message_ids": event["message_ids"],
                'reader_id': self.scope["user"].id,
            })
        )

    