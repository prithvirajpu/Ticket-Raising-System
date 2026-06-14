from rest_framework import status
from apps.tickets.models import Ticket,TicketAssignment,ClientSubscription,TicketSLATracking,TicketReview,TicketActivity,Notification
from apps.tickets.serializer import TicketSerializer,TicketActivitySerializer
from apps.tickets.utils import send_notification
from django.db import transaction
from django.utils import timezone
from datetime import timedelta
from django.db.models import Q
from django.core.paginator import Paginator
from django.contrib.auth import get_user_model
import logging
logger= logging.getLogger(__name__)

User=get_user_model()

ISSUE_PRIORITY_MAP = {
    "PAYMENT_ISSUE": "HIGH",
    "REFUND_ISSUE": "HIGH",
    "DELIVERY_ISSUE": "MEDIUM",
    "ORDER_ISSUE": "MEDIUM",
    "PRODUCT_ISSUE": "LOW",
    "ACCOUNT_ISSUE": "HIGH",
}
def create_ticket_service(data,user):
    from .attach_sla_to_ticket import attach_sla_to_ticket
    client_user = getattr(user, "client_user", None)

    if not client_user:
        return {
            "data": None,
            "errors": {
                "details": "User not linked to any client"
            },
            "status": status.HTTP_400_BAD_REQUEST
        }
    client = client_user.client_profile
    
    subscription=ClientSubscription.objects.filter(client=client,status='ACTIVE').first()
    if not subscription:
        return {
            "data":None,
            "errors":{'details':'No active subscription'},
            'status':status.HTTP_403_FORBIDDEN
        }

    try:
        with transaction.atomic(): 
            team_lead = client.team_lead
            if not team_lead:
                return {
                    "data": None,
                    "errors": {"details": "No team lead assigned to client"},
                    "status": status.HTTP_400_BAD_REQUEST
                }
            agents=User.objects.filter(role='AGENT',team_lead=team_lead,is_active=True,is_certified_agent=True,)
            if not agents.exists():
                return {
                    "data": None,
                    "errors": {"details": "No agents under this team lead"},
                    "status": status.HTTP_400_BAD_REQUEST
                }
            issue_type = data.get("issue_type")
            priority= ISSUE_PRIORITY_MAP.get(issue_type,'MEDIUM')

            ticket=Ticket.objects.create(
                subject=data.get('subject'),
                description=data.get('description'),
                issue_type=issue_type,
                priority=priority,
                client=client,
                created_by=user,
                assigned_to=None,
                status="OPEN"
                )
            TicketActivity.objects.create(ticket=ticket,action='CREATED',performed_by=user,description='Ticket created by customer')
            attach_sla_to_ticket(ticket)
            expiry_time=timezone.now()+timedelta(minutes=2)
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
        logger.exception("Ticket creation failed")
        return {
            'data':None,
            "errors":{'details':str(e)},
            "status":status.HTTP_400_BAD_REQUEST
        }

def get_ticket_list_service(request,sort='newest',search='',page=1,per_page=5):
    tickets = Ticket.objects.filter(created_by=request.user).select_related()
    if search:
        tickets=tickets.filter(Q(subject__icontains=search) | Q(ticket_code__icontains=search) | Q(description__icontains=search))

    if sort=='oldest': 
            tickets=tickets.order_by('created_at')
    else:
        tickets=tickets.order_by('-created_at')

    paginator= Paginator(tickets,per_page)
    page_obj= paginator.get_page(page)
    
    ticket_data = []
    for ticket in page_obj:
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
        "data": {'message': ticket_data,
                 "pagination": {
                "current_page": page_obj.number,
                "total_pages": paginator.num_pages,
                "total_items": paginator.count,
                "has_next": page_obj.has_next(),
                "has_previous": page_obj.has_previous(),
            },'sort':sort},
        "errors": {},
        "status": status.HTTP_200_OK
    }

def get_ticket_detail_service(ticket_id, request):
    try:
        ticket = Ticket.objects.filter(id=ticket_id).first()

        if not ticket:
            return {
                'data': None,
                "errors": {'details': 'Ticket not found'},
                'status': status.HTTP_404_NOT_FOUND
            }

        # Only internal staff must be assigned to the ticket
        if request.user.role != "USER":
            ticket = Ticket.objects.filter(
                id=ticket_id,
                assigned_to=request.user
            ).first()

            if not ticket:
                return {
                    'data': None,
                    "errors": {'details': "Ticket not assigned to this agent"},
                    'status': status.HTTP_403_FORBIDDEN
                }

        # Customer can only view their own tickets
        else:
            if ticket.created_by_id != request.user.id:
                return {
                    'data': None,
                    "errors": {'details': "You do not have permission to view this ticket"},
                    'status': status.HTTP_403_FORBIDDEN
                }

        serializer = TicketSerializer(ticket, context={"request": request})

        return {
            "data": {"message": serializer.data},
            "errors": {},
            "status": status.HTTP_200_OK
        }

    except Exception as e:
        return {
            "data": None,
            'errors': {'details': str(e)},
            'status': status.HTTP_400_BAD_REQUEST
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
            TicketActivity.objects.create(
                ticket=ticket,
                action="CLOSED",
                performed_by=user,
                description="Customer closed the ticket"
            )
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
    send_notification(
            user_id=ticket.assigned_to_id,
            notification_type="TICKET_REVIEWED",
            title="Customer Feedback Received",
            message=f"Customer rated Ticket #{ticket.ticket_code} with {rating} stars",
            data={
                "ticket_id": ticket.id,
                "ticket_code": ticket.ticket_code,
                "rating": rating,
            }
        )
    return {
            "data": {'message':'Review submitted successfully'},
            "errors": {},
            "status": status.HTTP_200_OK
            }

def reopen_ticket_service(user,ticket_id):
    try:
        with transaction.atomic():
            ticket=Ticket.objects.filter(id=ticket_id,created_by=user).first()
            if not ticket:
                return {
                    'data':None,
                    "errors":{'details':'Ticket not found'},
                    'status':status.HTTP_404_NOT_FOUND
                }
            if ticket.status !='RESOLVED':
                return{
                    'data':None,
                    "errors":{'details':'Only resolved tickets can be reopened'},
                    'status':status.HTTP_400_BAD_REQUEST
                }
            ticket.status='IN_PROGRESS'
            ticket.save(update_fields=['status'])
            send_notification(user_id=ticket.assigned_to_id,
                    notification_type="TICKET_REOPENED",
                    title="Ticket Reopened",
                    message=f"Ticket #{ticket.ticket_code} has been re-opened",
                    data={"ticket_id": ticket.id,"ticket_code": ticket.ticket_code}   
                )

            TicketActivity.objects.create(
                ticket=ticket,
                action="REOPENED",
                performed_by=user,
                description="Customer reopened the ticket"
            )
            return{
                'errors':{},
                "data":{'message':'Ticket reopened successfully'},
                'status':status.HTTP_200_OK
            }
    except Exception as e:
        return {
            'data':None,
            "errors":{'details':str(e)},
            'status':status.HTTP_500_INTERNAL_SERVER_ERROR
        }
    
def timeline_service(ticket_id):
    activities= TicketActivity.objects.filter(ticket_id=ticket_id).order_by('created_at')
    serializer= TicketActivitySerializer(activities,many=True)
    return {
        'data':{'message':serializer.data},
        'errors':None,
        'status':status.HTTP_200_OK
    }
