from rest_framework import status
from tickets.models import Ticket

def get_team_lead_tickets_service(user):
    try:
        tickets=Ticket.objects.filter(assigned_to=user,status='ESCALATED').order_by('-updated_at')
        data=[{'id':i.id,
               'ticket_code':i.ticket_code,
               'subject':i.subject,
               'priority':i.priority,
               'status':i.status,
               'created_at':i.created_at,
               } for i in tickets]
        return {
            'data':{'message':data},
            'errors':{},
            'status':status.HTTP_200_OK
        }
    except Exception as e:
        return {
            'data':None,
            'errors':{'details':str(e)},
            'status':status.HTTP_400_BAD_REQUEST
        }
