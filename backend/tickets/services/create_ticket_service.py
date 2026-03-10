from rest_framework import status
from tickets.models import Ticket,TicketAssignment
from tickets.serializer import TicketSerializer
from django.db import transaction
from django.utils import timezone
from datetime import timedelta
from django.contrib.auth import get_user_model
User=get_user_model()

def create_ticket_service(data,user):
    agents=User.objects.filter(role="AGENT",is_active=True)

    try:
        with transaction.atomic(): 
            ticket=Ticket.objects.create(
            subject=data.get('subject'),
            description=data.get('description'),
            issue_type=data.get('issue_type'),
            client=user,
            created_by=user,
            assigned_to=None,
            status="OPEN"
            )
            expiry_time=timezone.now()+timedelta(minutes=10)
            assignments=[
                TicketAssignment(ticket=ticket,agent=agent,status='PENDING',expires_at=expiry_time)
                for agent in agents
            ]
            TicketAssignment.objects.bulk_create(assignments)
            return {
                "data":{'message':'Ticket created and sent to agents'},
                "errors":{},
                "status":status.HTTP_201_CREATED
            }
        
    except Exception as e:
        return {
            'data':None,
            "errors":str(e),
            "status":status.HTTP_400_BAD_REQUEST
        }

def get_ticket_list_service(request):
    try:
        tickets=Ticket.objects.all().order_by('-created_at')
        serializer=TicketSerializer(tickets,many=True)
        return {
            "data":serializer.data,
            "errors":{},
            "status":status.HTTP_200_OK
        }
    except Exception as e:
        return {
            'data':None,
            "errors":str(e),
            "status":status.HTTP_400_BAD_REQUEST
        }
    
def get_ticket_detail_service(ticket_id):
    try:
        ticket=Ticket.objects.filter(id=ticket_id).first()
        if not ticket:
            return{
                'data':None,
                "errors":{'details':'Ticket not found'},
                'status':status.HTTP_404_NOT_FOUND
            }
        serializer=TicketSerializer(ticket)
        return {
            "data":serializer.data,
            'errors':{},
            "status":status.HTTP_200_OK
        }
    except Exception as e:
        return{
            "data":None,
            'errors':str(e),
            'status':status.HTTP_400_BAD_REQUEST
        }
    
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
    
