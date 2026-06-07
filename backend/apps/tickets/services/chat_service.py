from apps.tickets.models import Ticket,TicketChat,TicketChatParticipant,Notification
from django.core.exceptions import ObjectDoesNotExist
from rest_framework.exceptions import PermissionDenied,ValidationError
from apps.tickets.serializer import TicketChatSerializer
from apps.tickets.utils import send_notification
import logging
logger=logging.getLogger(__name__)

def send_message_service(user,ticket_id,message):
    try:
        ticket=Ticket.objects.get(id=ticket_id)
    except Ticket.DoesNotExist:
        raise ValidationError('Ticket not found')
    
    is_participant= TicketChatParticipant.objects.filter(ticket=ticket,user=user).exists()
    
    if not is_participant:
        raise PermissionDenied('Not allowed')
    if not ticket.assigned_to:
        raise ValidationError('chat not active yet')
    if not message or not message.strip():
        raise ValidationError('Message cannot be empty')
    
    chat= TicketChat.objects.create(ticket=ticket,sender=user,message=message)
    if user.id == ticket.created_by_id:
        receiver_id = ticket.assigned_to_id
    else:
        receiver_id = ticket.created_by_id
    notification = Notification.objects.filter(
        user_id=receiver_id,
        notification_type="CHAT_MESSAGE",
        is_read=False,
        data__ticket_id=ticket.id
    ).first()

    if notification:
        notification.message = f"{user.name}: {message}"
        notification.save(update_fields=["message"])
    else:
        send_notification(
            user_id=receiver_id,
            notification_type="CHAT_MESSAGE",
            title="New Message",
            message=f"{user.name }: sent you a message",
            data={
                "ticket_id": ticket.id,
                "ticket_code": ticket.ticket_code
            }
        )
    
    return {
        "data": TicketChatSerializer(chat).data,
        "errors": None,
        "status": 200
    }

def get_messages_service(user,ticket_id,request=None):
    try:
        ticket=Ticket.objects.get(id=ticket_id)
    except Ticket.DoesNotExist:
        raise ValidationError('Ticket not found')
    
    is_participant= TicketChatParticipant.objects.filter(ticket=ticket,user=user).exists()

    if not is_participant:
        raise PermissionDenied('Not allowed')
    
    chats=TicketChat.objects.filter(ticket=ticket).order_by('created_at')
    serialized = TicketChatSerializer(chats, many=True,context={"user": user}).data
    logger = logging.getLogger(__name__)
    first_chat = chats.first()

    if first_chat:
        logger.info("CHAT DEBUG: %s", first_chat.__dict__)
    else:
        logger.info("No chats found")

    return {
        "data": serialized,
        "errors": None,
        "status": 200
    }