from channels.layers import get_channel_layer
from channels.db import database_sync_to_async

from apps.tickets.models import Notification

async def async_send_notification(
    user_id,
    notification_type,
    title,
    message,
    data=None
):
    notification = await database_sync_to_async(
        Notification.objects.create
    )(
        user_id=user_id,
        notification_type=notification_type,
        title=title,
        message=message,
        data=data or {}
    )

    channel_layer = get_channel_layer()

    await channel_layer.group_send(
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