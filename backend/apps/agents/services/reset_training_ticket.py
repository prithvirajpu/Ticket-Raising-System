from rest_framework import status
from apps.agents.models import TrainingConversation
from apps.tickets.models import Ticket

import logging
logger=logging.getLogger(__name__)

def reset_training_ticket(request,ticket_id):
    try:
        ticket= Ticket.objects.get(id=ticket_id)
        
        TrainingConversation.objects.filter(
            ticket=ticket
        ).delete()

        ticket.training_score = 0
        ticket.training_passed = False
        ticket.training_feedback = ""
        ticket.status = "OPEN"

        ticket.save()

        return {
                "data": {
                    "message": 'The ticket is updated and resetted'
                },
                "errors": None,
                "status": status.HTTP_200_OK
            }
    except Exception as e:
        logger.exception('retry training failed')
        return {
            'data':None,
            'errors':{'details':str(e)},
            'status':status.HTTP_500_INTERNAL_SERVER_ERROR
        }