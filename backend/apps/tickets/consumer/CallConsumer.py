from channels.generic.websocket import AsyncJsonWebsocketConsumer
from apps.tickets.utils import async_send_notification
import json
import logging

logger = logging.getLogger(__name__)


class CallConsumer(AsyncJsonWebsocketConsumer):
    async def connect(self):
        user= self.scope['user']

        self.group_name=f"user_{user.id}"
        await self.channel_layer.group_add(
            self.group_name,
            self.channel_name
        )
        await self.accept()
        logger.info(
            "Call socket connected user=%s group=%s",
            user.id,
            self.group_name
        )

    async def disconnet(self,close_code):
        await self.channel_layer.group_discard(
            self.group_name,
            self.channel_name
        )
    async def receive_json(self,content):
        event_type = content.get("type")

        if event_type == "call_request":
            await self.handle_call_request(content)

        elif event_type == "call_accepted":
            await self.handle_call_accepted(content)

        elif event_type == "call_rejected":
            await self.handle_call_rejected(content)

        elif event_type == "call_ended":
            await self.handle_call_ended(content)

        elif event_type == "call_missed":
            await self.handle_call_missed(content)

    async def handle_call_request(self, data):
        try:
            customer_id = data.get("customer_id")
            caller = self.scope["user"]
            ticket_id = data.get("ticket_id")

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
                    "ticket_id": ticket_id,
                }
            )

            logger.info("group_send completed")

        except Exception:
            logger.exception("CALL REQUEST FAILED")

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

    async def call_accepted(self,event):
        await self.send(
            text_data=json.dumps({
                'type':'call_accepted',
                'peer_id':event['peer_id'],
            })
        )

    async def handle_call_rejected(self,data):
        caller_id= data['caller_id']

        await self.channel_layer.group_send(
            f'user_{caller_id}',
            {'type':'call_rejected'}
        )
    
    async def call_rejected(self,event):
        await self.send(text_data=json.dumps({
            'type':'call_rejected'
        }))

    async def handle_call_missed(self,data):
        customer_id = data.get("customer_id")

        await self.channel_layer.group_send(
            f'user_{customer_id}',
            {'type':'call_missed'}
        )
        await async_send_notification( user_id=customer_id,
            notification_type="MISSED_CALL",
            title="Missed Call",
            message="You have a missed call from Support Team.",
            data={})
    
    async def call_missed(self,event):
        await self.send(text_data=json.dumps({
            'type':'call_missed'
        }))

    async def handle_call_ended(self,data):
        customer_id = data.get("customer_id")
        receiver_id = data.get("receiver_id")
        await self.channel_layer.group_send(
            f'user_{customer_id}',
            {'type':'call_ended'}
        )

        await self.channel_layer.group_send(
            f'user_{receiver_id}',
            {'type':'call_ended'}
        )

    async def call_ended(self,event):
        await self.send(text_data=json.dumps({
            'type':'call_ended'
        }))
