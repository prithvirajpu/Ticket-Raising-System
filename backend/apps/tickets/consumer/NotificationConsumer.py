from channels.generic.websocket import AsyncJsonWebsocketConsumer 
import json
import logging

logger = logging.getLogger(__name__)

class NotificationConsumer(AsyncJsonWebsocketConsumer):
    async def connect(self):
        user=self.scope['user']
        self.group_name= f'user_{user.id}'

        await self.channel_layer.group_add(
            self.group_name,
            self.channel_name
        )
        await self.accept()
    
    async def disconnect(self, close_code):
        await self.channel_layer.group_discard(
            self.group_name,
            self.channel_name
        )
    
    async def notify(self, event):
        await self.send_json({
            "type": "notification",
            "notification_type": event["notification_type"],
            "title": event["title"],
            "message": event["message"],
            "data": event["data"]
        })
    