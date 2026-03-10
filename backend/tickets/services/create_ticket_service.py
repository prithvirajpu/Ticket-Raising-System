from rest_framework import status
from tickets.models import Ticket
from tickets.serializer import TicketSerializer

def create_ticket_service(data,user):

    try:
        ticket=Ticket.objects.create(
        subject=data.get('subject'),
        description=data.get('description'),
        client=user,
        created_by=user
        )
        return {
            "data":ticket,
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