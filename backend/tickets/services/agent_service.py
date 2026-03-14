from rest_framework import status
from tickets.models import Ticket,TicketAssignment,TicketSLATracking
from django.db import transaction
from django.utils import timezone
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
                assignment = TicketAssignment.objects.select_for_update().filter(
                    ticket_id=ticket_id,
                    agent=user
                ).first()

                if not assignment:
                    return {
                        "data":None,
                        "errors":{'details':'No ticket is assigned here'},
                        'status':status.HTTP_400_BAD_REQUEST
                    }
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
            ticket.save(update_fields=['status','assigned_to'])

            sla=TicketSLATracking.objects.filter(ticket=ticket).first()
            if sla and not sla.first_response_at:
                sla.first_response_at=timezone.now()
                sla.save(update_fields=['first_response_at'])

            TicketAssignment.objects.filter(ticket_id=ticket_id).exclude(agent=user).update(status='CANCELLED')

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
                    .select_related('ticket','ticket__client').order_by('-created_at'))
        print(user.id)
        serializer=AgentTicketRequestSerializer(assignments,many=True)
        print('hello we are here',serializer.data)
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

    assignment=TicketAssignment.objects.filter(ticket_id=ticket_id,agent=user).select_related('ticket','ticket__client').first()
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

            sla= TicketSLATracking.objects.filter(ticket=ticket).first()
            if sla:
                if timezone.now()<=sla.sla_deadline:
                    sla.sla_status='MET'
                else:
                    sla.sla_status='BREACHED'
                sla.save(update_fields=['sla_status'])

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