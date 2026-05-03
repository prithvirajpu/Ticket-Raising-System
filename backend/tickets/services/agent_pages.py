from tickets.models import TicketAssignment
from tickets.serializer import TicketSerializer
from rest_framework import status

def fetch_fake_tickets_service(user):
    try:
        assignments= TicketAssignment.objects.filter(agent=user,ticket__is_ai_generated=True).select_related('ticket').order_by('-created_at')

        tickets=[ i.ticket for i in assignments]
        serialized_data= TicketSerializer(tickets,many=True).data
        return {
            'data':{'message':serialized_data},
            'errors':{},
            'status':status.HTTP_200_OK
        }
        
    except Exception as e:
        return {
            "data": None,
            "errors": {"details": str(e)},
            "status": status.HTTP_500_INTERNAL_SERVER_ERROR
        }
    
def get_fake_ticket_detail_service(agent,id):
    try:
        assignment=TicketAssignment.objects.filter(agent=agent,ticket_id=id,ticket__is_ai_generated=True).select_related('ticket').first()
        if not assignment:
            return {
                'data':{},
                'errors':{'details':'Ticket not found'},
                'status':status.HTTP_400_BAD_REQUEST
            }
        valid_data=TicketSerializer(assignment.ticket).data
        return {
            'data':{'message':valid_data},
                'errors':{},
                'status':status.HTTP_200_OK
        }
    except Exception as e:
        return {
            "data": None,
            "errors": {"details": str(e)},
            "status": status.HTTP_500_INTERNAL_SERVER_ERROR
        }