from rest_framework.views import APIView
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response

from tickets.serializer import TicketSerializer
from tickets.services import create_ticket_service

class CreateTicketView(APIView):
    permission_classes=[IsAuthenticated]

    def post(self,request):
        ticket=create_ticket_service(request.data,request.user)
        serializer=TicketSerializer(ticket)

        return Response(serializer.data)