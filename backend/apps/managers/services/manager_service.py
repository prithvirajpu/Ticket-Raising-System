from apps.tickets.models import Ticket
from rest_framework import status

def get_manager_tickets_service(user):
    try:
        tickets=Ticket.objects.filter(assigned_to=user,status__in=['ESCALATED','IN_PROGRESS']).order_by('-updated_at')
        data=[{
            "id": t.id,
            "ticket_code": t.ticket_code,
            "subject": t.subject,
            "priority": t.priority,
            "status": t.status,
            "created_at": t.created_at,
        } for t in tickets]
        return {
            "data": {"message": data},
            "errors": {},
            "status": status.HTTP_200_OK
        }

    except Exception as e:
        return {
            "data": None,
            "errors": {"details": str(e)},
            "status": status.HTTP_400_BAD_REQUEST
        }