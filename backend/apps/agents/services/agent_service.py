from rest_framework import status
from apps.tickets.models import Ticket,TicketAssignment,TicketSLATracking,TicketChatParticipant,TicketActivity
from django.db import transaction
from django.utils import timezone
from decimal import Decimal
from django.db.models import Q
from apps.tickets.serializer import AgentTicketRequestSerializer,TicketSerializer
from django.contrib.auth import get_user_model
from django.core.paginator import Paginator
from apps.payments.services import debit_wallet

User=get_user_model()

def accept_ticket_service(ticket_id, user):
    try:
        with transaction.atomic():

            ticket = Ticket.objects.select_for_update().get(id=ticket_id)

            if ticket.assigned_to:
                return {
                    "data": None,
                    "errors": {"details": "Ticket already accepted by another agent"},
                    "status": status.HTTP_400_BAD_REQUEST
                }

            assignments = TicketAssignment.objects.select_for_update().filter(ticket_id=ticket_id)

            assignment = assignments.filter(agent=user).first()

            if not assignment:
                return {
                    "data": None,
                    "errors": {"details": "No ticket is assigned here"},
                    "status": status.HTTP_400_BAD_REQUEST
                }

            from django.utils import timezone

            if assignment.status != "PENDING" or (
                assignment.expires_at and assignment.expires_at < timezone.now()
            ):
                return {
                    "data": None,
                    "errors": {"details": "Ticket expired or already processed"},
                    "status": status.HTTP_400_BAD_REQUEST
                }

            ticket.status = "IN_PROGRESS"
            ticket.assigned_to = user
            ticket.save(update_fields=['status', 'assigned_to'])
            TicketChatParticipant.objects.get_or_create(
                        ticket=ticket,
                        user=ticket.created_by,
                        defaults={"role": "USER"}
                    )

            TicketChatParticipant.objects.get_or_create(
                        ticket=ticket,
                        user=user,
                        defaults={"role": "AGENT"}
                    )

            assignment.status = "ACCEPTED"
            assignment.expires_at = None
            assignment.save(update_fields=['status', 'expires_at'])
            TicketActivity.objects.create(ticket=ticket,action='ACCEPTED',performed_by=user,description='Agent accepted the ticket')

            assignments.filter(status="PENDING").exclude(agent=user).update(status="CANCELLED")

            # SLA
            sla = TicketSLATracking.objects.filter(ticket=ticket).first()
            if sla and not sla.first_response_at:
                sla.first_response_at = timezone.now()
                sla.save(update_fields=['first_response_at'])

            return {
                "data": {"message": "Ticket accepted successfully"},
                "errors": None,
                "status": status.HTTP_200_OK
            }

    except Exception as e:
        return {
            'data': None,
            'errors': {'details': f'Failed to accept the ticket: {str(e)}'},
            'status': status.HTTP_500_INTERNAL_SERVER_ERROR
        } 
    
def reject_ticket_service(ticket_id,user,reason):
    try:
        with transaction.atomic():
            assignment=TicketAssignment.objects.select_for_update().get(ticket_id=ticket_id,agent=user,status='PENDING')
            pending_count= TicketAssignment.objects.filter(ticket_id=ticket_id,status='PENDING').count()
            
            if pending_count<=1:
                return {
                    'data':None,
                    'errors':{'details':'Last assigned agent cannot reject the ticket'},
                    'status':status.HTTP_400_BAD_REQUEST
                }
            assignment.status='REJECTED'
            assignment.rejection_reason=reason
            assignment.save()
            debit_wallet(
                user=user,
                amount=Decimal("10.00"),
                transaction_type='PENALTY',
                description=f'Penalty for rejecting ticket{assignment.ticket.ticket_code}',
                created_by=None,
            )
        return {
            'data':{"message":'Ticket rejected'},
            'errors':None,
            'status':status.HTTP_200_OK
        }
    except TicketAssignment.DoesNotExist:
        return {
            "data": None,
            "errors": {"details": "No pending assignment found"},
            "status": status.HTTP_404_NOT_FOUND
        }
    
def get_agent_ticket_requests_service(user,sort='newest',search='',page=1,page_size=5):
    try:
        assignments=(TicketAssignment.objects.filter(agent=user,status='PENDING')
                    .select_related('ticket','ticket__client'))
        if search:
            assignments=assignments.filter(Q(ticket__subject__icontains=search) | 
                                           Q(ticket__ticket_code__icontains=search) | 
                                           Q(ticket__description__icontains=search))

        if sort=='oldest': 
            assignments=assignments.order_by('ticket__created_at')
        else:
            assignments=assignments.order_by('-ticket__created_at')
        
        paginator=Paginator(assignments,page_size)
        page_obj=paginator.get_page(page)

        serializer=AgentTicketRequestSerializer(page_obj.object_list,many=True)
        return {
            'data': {
                'message': serializer.data,
                'pagination': {
                    'current_page': page_obj.number,
                    'total_pages': paginator.num_pages,
                    'has_next': page_obj.has_next(),
                    'has_previous': page_obj.has_previous(),
                    'total_items': paginator.count
                },
                'sort': sort
            },
            "errors": {},
            'status': status.HTTP_200_OK
        }
    except Exception as e:
        print("ERROR:", str(e)) 
        return{
            "data":None,
            'errors':{'details':str(e)},
            'status':status.HTTP_400_BAD_REQUEST
        }
    
def get_agent_ticket_detail_service(request,ticket_id):

    ticket=Ticket.objects.filter(id=ticket_id,assigned_to=request.user).first()
    if not ticket:
        return {
            'data':None,
            "errors":{'details':"Ticket not assigned to this agent"},
            'status':status.HTTP_403_FORBIDDEN
        }
    serializer=TicketSerializer(ticket, context={"request": request})
    return {
        'data':{'message':serializer.data},
        "errors":{},
        'status':status.HTTP_200_OK
    }

def get_agent_ongoing_tickets_service(user,sort='newest',search='',page=1, page_size=5):
    try:
        tickets=Ticket.objects.filter(assigned_to=user,status='IN_PROGRESS')
        if search:
            tickets=tickets.filter(Q(subject__icontains=search) | Q(ticket_code__icontains=search) | Q(description__icontains=search))

        if sort=='oldest': 
            tickets=tickets.order_by('created_at')
        else:
            tickets=tickets.order_by('-created_at')

        paginator = Paginator(tickets, page_size)
        page_obj = paginator.get_page(page)

        serializer=TicketSerializer(page_obj.object_list,many=True)
        return {
            'data': {
                'message': serializer.data,
                'pagination': {
                    'current_page': page_obj.number,
                    'total_pages': paginator.num_pages,
                    'has_next': page_obj.has_next(),
                    'has_previous': page_obj.has_previous(),
                    'total_items': paginator.count
                },
                'sort': sort
            },
            "errors": {},
            'status': status.HTTP_200_OK
        }
    except Exception as e:
        return {
            "data": None,
            "errors": {"details": str(e)},
            "status": status.HTTP_400_BAD_REQUEST
        }
    

    
