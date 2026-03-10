from rest_framework import status
from tickets.models import Ticket,TicketAssignment
from django.db import transaction
from django.contrib.auth import get_user_model
User=get_user_model()

def accept_ticket_service(ticket_id,user):
    try:
        with transaction.atomic():
            try:
                ticket=Ticket.objects.select_for_update().get(id=ticket_id)
                if ticket.assigned_to:
                    return {
                        "data":None,
                        'errors':{'details':"Ticket already accepted by another agent"},
                        'status':status.HTTP_400_BAD_REQUEST
                    }
                assignment = TicketAssignment.objects.select_for_update().get(
                    ticket_id=ticket_id,
                    agent=user
                )
            except TicketAssignment.DoesNotExist:
                return {
                    "data": None,
                    "errors": {"details": "No assignment request"},
                    "status": status.HTTP_404_NOT_FOUND
                }

            if assignment.status != "PENDING":
                return {
                    "data": None,
                    "errors": {"details": "Ticket already accepted"},
                    "status": status.HTTP_400_BAD_REQUEST
                }

            assignment.status = "ACCEPTED"
            assignment.save()

            ticket = assignment.ticket
            ticket.status = "IN_PROGRESS"
            ticket.assigned_to = user
            ticket.save()

            return {
                "data": {"message": "Ticket accepted successfully"},
                "errors": None,
                "status": status.HTTP_200_OK
            }

    except Exception as e:
        return{
            'data':None,
            'errors':f'Failed to accept the ticket :{str(e)}',
            'status':status.HTTP_500_INTERNAL_SERVER_ERROR
        }
    
def reject_ticket_service(ticket_id,user,reason):
    try:
        with transaction.atomic():
            assignment=TicketAssignment.objects.select_for_update().get(ticket_id=ticket_id,agent=user,status='PENDING')
        
            assignment.status='REJECTED'
            assignment.rejection_reason=reason
            assignment.save()
        return {
            'data':{"message":'Ticket rejected'},
            'status':status.HTTP_200_OK
        }
    except TicketAssignment.DoesNotExist:
        return {
            "data": None,
            "errors": {"details": "No pending assignment found"},
            "status": status.HTTP_404_NOT_FOUND
        }