from apps.agents.models import TrainingConversation
from apps.tickets.models import TicketAssignment
import logging

logger = logging.getLogger(__name__)

def get_training_messages_service(request,ticket_id):
    logger.info("ticket_id =%s", ticket_id)
    logger.info("user =%s", request.user.id)
    assignment= TicketAssignment.objects.get(ticket_id=ticket_id,agent=request.user)

    messages = TrainingConversation.objects.filter(
        assignment=assignment
    ).order_by("created_at")

    data = []

    for msg in messages:
        data.append({
            "id": msg.id,
            "message": msg.message,
            "sender_type": msg.sender_type,
            "created_at": msg.created_at,
        })

    return {
        "data": data,
        "errors": {},
        "status": 200
    }