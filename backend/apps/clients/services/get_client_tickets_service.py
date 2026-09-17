from django.core.paginator import Paginator
from django.db.models import Count
from rest_framework import status
from apps.tickets.models import Ticket

def get_client_tickets_service(request):
    try:
        user=request.user
        try:
            client_profile=user.client_profile
        except Exception:
            return {
                'data':None,
                'errors':{'details':'Client profile not found'},
                'status':status.HTTP_400_BAD_REQUEST
            }
        all_tickets=Ticket.objects.filter(client=client_profile,created_by__role='USER',
                                          is_ai_generated=False,)
        statistics={
            'total':all_tickets.count(),
            'open':all_tickets.filter(status='OPEN').count(),
            'in_progress':all_tickets.filter(status='IN_PROGRESS').count(),
            'escalated':all_tickets.filter(status='ESCALATED').count(),
            'resolved':all_tickets.filter(status='RESOLVED').count(),
            'closed':all_tickets.filter(status='CLOSED').count(),
            'reopened':all_tickets.filter(status='REOPENED').count(),
        }
        tickets=all_tickets.select_related('created_by').order_by('-created_at')

        ticket_status=request.GET.get('status')
        if ticket_status and ticket_status !='ALL':
            valid_statuses=[choice[0] for choice in Ticket.STATUS_CHOICES]
            if ticket_status not in valid_statuses:
                return{
                     "data": None,
                    "errors": {
                        "details": "Invalid ticket status"
                    },
                    "status": status.HTTP_400_BAD_REQUEST,
                }
            tickets=tickets.filter(status=ticket_status)
        page_number=request.GET.get('page',1)
        paginator=Paginator(tickets,10)
        page_obj=paginator.get_page(page_number)

        ticket_data=[]
        for ticket in page_obj:
            ticket_data.append({
                "id": ticket.id,
                "ticket_code": ticket.ticket_code,
                "customer_name": (
                    ticket.created_by.name
                    or ticket.created_by.email
                ),
                "customer_email": ticket.created_by.email,
                "subject": ticket.subject,
                "issue_type": ticket.issue_type,
                "priority": ticket.priority,
                "status": ticket.status,
                "is_ai_generated": ticket.is_ai_generated,
                "created_at": ticket.created_at,
                "updated_at": ticket.updated_at,
            })
        paginator_data={
            "count": paginator.count,
            "total_pages": paginator.num_pages,
            "current_page": page_obj.number,
            "page_size": 10,
            "has_next": page_obj.has_next(),
            "has_previous": page_obj.has_previous(),
        }
        result = {
            "data": {
                "statistics": statistics,
                "tickets": ticket_data,
            },
            "errors": {},
            "status": status.HTTP_200_OK,
            "paginator": paginator_data,
        }
        return result
    except Exception as e:
        import traceback

        print("GET CLIENT TICKETS SERVICE ERROR ❌")
        print("ERROR:", str(e))
        traceback.print_exc()
        print('Get client tickets service error',str(e))
        return {
            "data": None,
            "errors": {
                "details": "Something went wrong while fetching tickets"
            },
            "status": status.HTTP_500_INTERNAL_SERVER_ERROR,
        }
