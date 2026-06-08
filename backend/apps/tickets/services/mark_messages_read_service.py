# apps/tickets/services.py

from django.utils import timezone
from apps.tickets.models import TicketChat,MessageRead


from django.utils import timezone
from apps.tickets.models import TicketChat, MessageRead

def mark_messages_read_service(ticket_id, user):
    messages = TicketChat.objects.filter(
        ticket_id=ticket_id
    ).exclude(sender=user)

    message_ids = []

    for msg in messages:
        obj, created = MessageRead.objects.get_or_create(
            message=msg,
            user=user
        )
        if created:
            message_ids.append(msg.id)

    return message_ids