from apps.tickets.models import Notification
import logging
logger=logging.getLogger(__name__)

def mark_chat_notifications_read(ticket_id, user):

    updated=Notification.objects.filter(
        user=user,
        notification_type="CHAT_MESSAGE",
        is_read=False,
        data__ticket_id=int(ticket_id)
    ).update(is_read=True)
    logger.info("UPDATED NOTIFICATIONS =%s", updated)