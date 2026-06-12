from rest_framework import status
from apps.agents.models import TrainingConversation
from apps.tickets.models import TicketAssignment

import logging
logger=logging.getLogger(__name__)

def reset_training_ticket(request,ticket_id):
    try:
        assignment= TicketAssignment.objects.get(ticket_id=ticket_id,agent=request.user)
        
        TrainingConversation.objects.filter(
            assignment=assignment
        ).delete()

        assignment.training_score = 0
        assignment.training_passed = False
        assignment.training_feedback = ""
        assignment.status = "NOT_STARTED"

        assignment.save()

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