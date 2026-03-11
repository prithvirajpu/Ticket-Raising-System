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
            "errors":{'details':str(e)},
            "status":status.HTTP_400_BAD_REQUEST
        }

def get_ticket_list_service(request):
    try:
        tickets=Ticket.objects.filter(client=request.user).order_by('-created_at')
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
 