from rest_framework import status
from tickets.models import Ticket,TicketAssignment,ClientSubscription
from tickets.serializer import TicketSerializer
from django.db import transaction
from django.utils import timezone
from datetime import timedelta
from django.contrib.auth import get_user_model

User=get_user_model()

def create_ticket_service(data,user):
    from tickets.services import attach_sla_to_ticket
    agents=User.objects.filter(role="AGENT",is_active=True)
    subscription=ClientSubscription.objects.filter(client=user.client,status='ACTIVE').first()
    if not subscription:
        return {
            "data":None,
            "errors":{'details':'No active subscription'},
            'status':status.HTTP_403_FORBIDDEN
        }

    try:
        with transaction.atomic(): 
            ticket=Ticket.objects.create(
            subject=data.get('subject'),
            description=data.get('description'),
            issue_type=data.get('issue_type'),
            priority=data.get('priority','MEDIUM'),
            client=user.client,
            created_by=user,
            assigned_to=None,
            status="OPEN"
            )
            attach_sla_to_ticket(ticket)
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
            "errors":{'details':str(e)},
            "status":status.HTTP_400_BAD_REQUEST
        }

def get_ticket_list_service(request):
    try:
        tickets=Ticket.objects.filter(client=request.user.client).order_by('-created_at')
        serializer=TicketSerializer(tickets,many=True)
        return {
            "data":{'message':serializer.data},
            "errors":{},
            "status":status.HTTP_200_OK
        }
    except Exception as e:
        return {
            'data':None,
            "errors":{'details':str(e)},
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
            "data":{'message':serializer.data},
            'errors':{},
            "status":status.HTTP_200_OK
        }
    except Exception as e:
        return{
            "data":None,
            'errors':{'details':str(e)},
            'status':status.HTTP_400_BAD_REQUEST
        }
 
def close_ticket_service(user,ticket_id):
    try:
        with transaction.atomic():
            ticket=Ticket.objects.filter(client=user.client,id=ticket_id).first()

            if not ticket:
                return {
                    "data": None,
                    "errors": {"details": "Ticket not found"},
                    "status": status.HTTP_404_NOT_FOUND
                }
            if ticket.status !='RESOLVED':
                return{
                    "data": None,
                    "errors": {"details": "Ticket must be resolved first"},
                    "status": status.HTTP_400_BAD_REQUEST
                }
            ticket.status='CLOSED'
            ticket.save(update_fields=['status'])
            return {
                    "data": {'message':'Ticket closed successfully'},
                    "errors": {},
                    "status": status.HTTP_200_OK
                }
    except Exception as e:
        return {
            "data": None,
            "errors": {"details": str(e)},
            "status": status.HTTP_500_INTERNAL_SERVER_ERROR
        }