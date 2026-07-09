from apps.agents.models import (TrainingConversation)
from apps.tickets.models import (Ticket,TicketAssignment)
from channels.db import database_sync_to_async
import logging
logger = logging.getLogger(__name__)

@database_sync_to_async
def save_agent_message(assignment, message):

    return TrainingConversation.objects.create(
        assignment=assignment,
        sender_type='AGENT',
        message=message
    )

@database_sync_to_async
def save_ai_message(assignment, message):

    return TrainingConversation.objects.create(
        assignment=assignment,
        sender_type='AI_CUSTOMER',
        message=message
    )

@database_sync_to_async
def build_ai_history(assignment):

    conversations = TrainingConversation.objects.filter(
    assignment=assignment
).order_by("created_at")

    messages = []

    for msg in conversations:

        if msg.sender_type == "AGENT":
            messages.append({
                "role": "user",
                "content": msg.message
            })

        else:
            messages.append({
                "role": "assistant",
                "content": msg.message
            })

    return messages

@database_sync_to_async
def get_ticket(ticket_id):
    return Ticket.objects.get(id=ticket_id)

@database_sync_to_async
def get_training_assignment(ticket_id, user_id):
    logger.info('ticket_id %s, userid %s',ticket_id,user_id)
    return TicketAssignment.objects.get(
        ticket_id=ticket_id,
        agent_id=user_id
    )

@database_sync_to_async
def mark_training_resolved(assignment):
    assignment.training_status = "RESOLVED"
    assignment.save(
        update_fields=["training_status"]
    )

@database_sync_to_async
def get_assignment(assignment_id):
    return TicketAssignment.objects.select_related(
        "ticket",
        "agent"
    ).get(id=assignment_id)