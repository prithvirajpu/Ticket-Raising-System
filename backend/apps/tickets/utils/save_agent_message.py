from apps.agents.models import (TrainingConversation)
from apps.tickets.models import (Ticket)
from channels.db import database_sync_to_async

@database_sync_to_async
def save_agent_message(ticket, message):

    return TrainingConversation.objects.create(
        ticket=ticket,
        sender_type='AGENT',
        message=message
    )

@database_sync_to_async
def save_ai_message(ticket, message):

    return TrainingConversation.objects.create(
        ticket=ticket,
        sender_type='AI_CUSTOMER',
        message=message
    )

@database_sync_to_async
def build_ai_history(ticket):

    conversations = TrainingConversation.objects.filter(
    ticket=ticket
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