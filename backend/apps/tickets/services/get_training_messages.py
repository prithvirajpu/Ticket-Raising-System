from apps.agents.models import TrainingConversation

def get_training_messages_service(ticket_id):
    messages = TrainingConversation.objects.filter(
        ticket_id=ticket_id
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