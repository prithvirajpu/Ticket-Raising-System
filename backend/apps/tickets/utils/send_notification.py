from asgiref.sync import async_to_sync
from channels.layers import get_channel_layer
from apps.tickets.models import Notification
import logging
logger = logging.getLogger(__name__)

def send_notification(
    user_id,
    notification_type,
    title,
    message,
    data=None
):
    notification = Notification.objects.create(
        user_id=user_id,
        notification_type=notification_type,
        title=title,
        message=message,
        data=data or {}
    )
    logger.info('sending WS notification TO %s',user_id)
    channel_layer = get_channel_layer()

    async_to_sync(channel_layer.group_send)(
        f"notifications_{user_id}",
        {
           "type": "notify",
            "id": notification.id,
            "notification_type": notification_type,
            "title": title,
            "message": message,
            "data": data or {},
            "is_read": False,
            "created_at": notification.created_at.isoformat(),
        }
    )