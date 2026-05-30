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
        self.user_room = f"user_{self.scope['user'].id}"
        logger.info('group for chat %s, group for call %s',self.room_group_name,self.user_room)

        await self.channel_layer.group_add(
            self.room_group_name,
            self.channel_name
        )
        await self.channel_layer.group_add(
            self.user_room,
            self.channel_name
        )

        await self.accept()

    async def disconnect(self, close_code):
        await self.channel_layer.group_discard(
            self.room_group_name,
            self.channel_name
        )
        await self.channel_layer.group_discard(
            self.user_room,
            self.channel_name
        )

    async def receive(self, text_data):
        try:
            data = json.loads(text_data)
            event_type=data.get('type')

            logger.info("WS: event %s", event_type)
            if event_type=='chat_message':
                await self.handle_chat_message(data)
            elif event_type=='call_request':
                await self.handle_call_request(data)
            elif event_type=='call_accepted':
                await self.handle_call_accepted(data)
            else:
                logger.warning('unknown event type: %s',event_type)

        except Exception as e:
            logger.error("WS ERROR: %s", str(e))

    async def handle_chat_message(self,data):
        message= data.get('message')
        user=self.scope['user']
        chat= await database_sync_to_async(send_message_service)(
            user=user,
            ticket_id=self.ticket_id,
            message=message
        )
        chat_data=chat.get('data',{})
        await self.channel_layer.group_send(
            self.room_group_name,
            {
                'type':'chat_message',
                "message": chat_data.get("message"),
                "sender_id": chat_data.get("sender_id"),
                "sender_name": chat_data.get("sender_name"),
                "created_at": chat_data.get("created_at"),
            }
        )
    
    async def handle_call_request(self, data):
        try:
            customer_id = data.get("customer_id")
            caller = self.scope["user"]

            logger.info("customer_id received = %s", customer_id)
            logger.info("caller here self.scope['user'] %s", caller)
            logger.info("sending to group user_%s", customer_id)

            await self.channel_layer.group_send(
                f"user_{customer_id}",
                {
                    "type": "incoming_call",
                    "caller_id": caller.id,
                    "caller_name": getattr(
                        caller,
                        "full_name",
                        caller.email
                    ),
                    "ticket_id": self.ticket_id,
                }
            )

            logger.info("group_send completed")

        except Exception:
            logger.exception("CALL REQUEST FAILED")

    async def handle_call_accepted(self,data):
        caller_id=data.get('caller_id')
        peer_id=data.get('peer_id')

        await self.channel_layer.group_send(
            f'user_{caller_id}',
            {
                'type':'call_accepted',
                'peer_id':peer_id
            }
        )
         
    async def incoming_call(self,event):
        logger.info('event in incoming call method %s',event)
        logger.info('incoming call=>caller= %s ticket= %s',
                    event['caller_id'],event['ticket_id'])
        await self.send(
            text_data=json.dumps({
                "type": "incoming_call",
                "caller_id": event["caller_id"],
                "caller_name": event["caller_name"],
                "ticket_id": event["ticket_id"],
            })
        )

    async def call_accepted(self,event):
        await self.send(
            text_data=json.dumps({
                'type':'call_accepted',
                'peer_id':event['peer_id'],
            })
        )

    async def chat_message(self, event):
        logger.info("EVENT DATA: %s", event)
        await self.send(text_data=json.dumps({
            'type':'chat_message',
            "message": event["message"],
            "sender_name": event["sender_name"],
            "sender_id": event["sender_id"],
            "created_at": event["created_at"],
        }))
