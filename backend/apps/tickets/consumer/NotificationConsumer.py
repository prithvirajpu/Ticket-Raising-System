from channels.generic.websocket import AsyncJsonWebsocketConsumer 
import json
import logging

logger = logging.getLogger(__name__)

class NotificationConsumer(AsyncJsonWebsocketConsumer):
    async def connect(self):
        try:
            user=self.scope['user']
            self.group_name= f'notifications_{user.id}'
            logger.info('notification connect called-user %s ',self.scope['user'])
            logger.info(
                "NotificationConsumer joined group=%s",
                self.group_name
            )

            await self.channel_layer.group_add(
                self.group_name,
                self.channel_name
            )
            await self.accept()
            logger.info('notification ws accepted')
        except Exception:
            logger.exception("CONNECT ERROR")
            raise
    
    async def disconnect(self, close_code):
        await self.channel_layer.group_discard(
            self.group_name,
            self.channel_name
        )
    
    async def notify(self, event):
        logger.info('notification event %s',event)
        await self.send_json({
            "type": "notification",
            "notification_type": event["notification_type"],
            "title": event["title"],
            "message": event["message"],
            "data": event["data"]
        })
    