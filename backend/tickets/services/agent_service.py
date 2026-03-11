from rest_framework import status
from tickets.models import Ticket,TicketAssignment
from django.db import transaction
from tickets.serializer import AgentTicketRequestSerializer,TicketSerializer
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
                    "errors": {"details": "Ticket already processed"},
                    "status": status.HTTP_400_BAD_REQUEST
                }

            assignment.status = "ACCEPTED"
            assignment.save(update_fields=['status'])

            ticket = assignment.ticket
            ticket.status = "IN_PROGRESS"
            ticket.assigned_to = user
            ticket.save()

            TicketAssignment.objects.filter(ticket_id=ticket_id).exclude(agent=user).delete()

            return {
                "data": {"message": "Ticket accepted successfully"},
                "errors": None,
                "status": status.HTTP_200_OK
            }

    except Exception as e:
        return{
            'data':None,
            'errors':{'details':f'Failed to accept the ticket :{str(e)}'},
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
    
def get_agent_ticket_requests_service(user):
    try:
        assignments=(TicketAssignment.objects.filter(agent=user,status='PENDING')
                    .select_related('ticket').order_by('-created_at'))
        serializer=AgentTicketRequestSerializer(assignments,many=True)
        return {
            'data':{'message':serializer.data},
            "errors":{},
            'status':status.HTTP_200_OK
        }
    except Exception as e:
        return{
            "data":None,
            'errors':{'details':str(e)},
            'status':status.HTTP_400_BAD_REQUEST
        }
    
def get_agent_ticket_detail_service(user,ticket_id):

    assignment=TicketAssignment.objects.filter(ticket_id=ticket_id,agent=user).select_related('ticket').first()
    if not assignment:
        return {
            'data':None,
            "errors":{'details':"Ticket not assigned to this agent"},
            'status':status.HTTP_403_FORBIDDEN
        }
    ticket=assignment.ticket
    serializer=TicketSerializer(ticket)
    return {
        'data':{'message':serializer.data},
        "errors":{},
        'status':status.HTTP_200_OK
    }

def get_agent_ongoing_tickets_service(user):
    try:
        tickets=Ticket.objects.filter(assigned_to=user,status='IN_PROGRESS').order_by('-created_at')
        serializer=TicketSerializer(tickets,many=True)
        return {
            'data':{'message':serializer.data},
            "errors":{},
            'status':status.HTTP_200_OK
        }
    except Exception as e:
        return {
            "data": None,
            "errors": {"details": str(e)},
            "status": status.HTTP_400_BAD_REQUEST
        }
    
def resolve_ticket_service(user,ticket_id):
    try:
        with transaction.atomic():
            ticket=Ticket.objects.filter(id=ticket_id,assigned_to=user).first()
            if not ticket:
                return {
                    "data": None,
                    "errors": {"details": "Ticket not assigned to this agent"},
                    "status": status.HTTP_403_FORBIDDEN
                }
            if ticket.status !='IN_PROGRESS':
                return {
                    "data": None,
                    "errors": {"details": "Ticket is not in progress"},
                    "status": status.HTTP_400_BAD_REQUEST
                }
            ticket.status='RESOLVED'
            ticket.save(update_fields=['status'])

            return {
                "data": {"message": "Ticket resolved successfully"},
                "errors": {},
                "status": status.HTTP_200_OK
            }
    except Exception as e:
        return {
            "data": None,
            "errors": {"details": str(e)},
            "status": status.HTTP_500_INTERNAL_SERVER_ERROR
        }