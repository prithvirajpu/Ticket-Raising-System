from rest_framework import status
from tickets.models import Ticket,TicketAssignment,ClientSubscription,TicketSLATracking,TicketReview
from tickets.serializer import TicketSerializer
from django.db import transaction
from django.utils import timezone
from datetime import timedelta
from django.db.models import Q
from django.contrib.auth import get_user_model

User=get_user_model()

def create_ticket_service(data,user):
    from tickets.services import attach_sla_to_ticket
    
    subscription=ClientSubscription.objects.filter(client=user.client,status='ACTIVE').first()
    if not subscription:
        return {
            "data":None,
            "errors":{'details':'No active subscription'},
            'status':status.HTTP_403_FORBIDDEN
        }

    try:
        with transaction.atomic(): 
            team_lead=user.client.team_lead
            if not team_lead:
                return {
                    "data": None,
                    "errors": {"details": "No team lead assigned to client"},
                    "status": status.HTTP_400_BAD_REQUEST
                }
            agents=User.objects.filter(role='AGENT',team_lead=team_lead,is_active=True)
            if not agents.exists():
                return {
                    "data": None,
                    "errors": {"details": "No agents under this team lead"},
                    "status": status.HTTP_400_BAD_REQUEST
                }
            
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

def get_ticket_list_service(request,sort='newest',search=''):
    tickets = Ticket.objects.filter(client=request.user.client)
    if search:
        tickets=tickets.filter(Q(subject__icontains=search) | Q(ticket_code__icontains=search) | Q(description__icontains=search))

    if sort=='oldest': 
            tickets=tickets.order_by('created_at')
    else:
        tickets=tickets.order_by('-created_at')
    
    ticket_data = []
    for ticket in tickets:
        # Safe SLA lookup
        sla_status = TicketSLATracking.objects.filter(ticket=ticket).values_list('sla_status', flat=True).first() or ''
        
        ticket_data.append({
            'id': ticket.id,
            'ticket_code': ticket.ticket_code,
            'subject': ticket.subject,
            'description': ticket.description or '',
            'status': ticket.status,
            'issue_type': ticket.issue_type,
            'priority': ticket.priority,
            'created_at': ticket.created_at,
            'sla_status': sla_status  # '' or 'MET'
        })
    return {
        "data": {'message': ticket_data,'sort':sort},
        "errors": {},
        "status": status.HTTP_200_OK
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
            ticket=Ticket.objects.filter(id=ticket_id).first()

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
    
def submit_review_service(user,ticket_id,rating,review):
    ticket=Ticket.objects.filter(id=ticket_id).first()
    if not ticket:
        return {
            "data": None,
            "errors": {"details": "Ticket not found"},
            "status": status.HTTP_404_NOT_FOUND
        }
    try:
        rating = int(rating)
    except:
        return {"data": None, "errors": {"details": "Rating must be a number"}, "status": 400}
    
    if rating < 1 or rating > 5:
        return {"data": None, "errors": {"details": "Rating must be 1-5"}, "status": 400}

    if ticket.status!='CLOSED':
        return {
            "data": None,
            "errors": {"details": "Only closed tickets can be reviewed"},
            "status": status.HTTP_400_BAD_REQUEST
        }
    if hasattr(ticket,"review"):
        return {
            "data": None,
            "errors": {"details": "Review already submitted"},
            "status": status.HTTP_400_BAD_REQUEST
        }

    TicketReview.objects.create(ticket=ticket,rating=rating,review=review)
    return {
            "data": {'message':'Review submitted successfully'},
            "errors": {},
            "status": status.HTTP_200_OK
            }