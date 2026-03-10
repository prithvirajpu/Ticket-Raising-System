from rest_framework.views import APIView
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response

from core_app.utils import return_response

from tickets.serializer import TicketSerializer
from tickets.services import create_ticket_service,get_ticket_list_service,get_ticket_detail_service,accept_ticket_service

class CreateTicketView(APIView):
    permission_classes=[IsAuthenticated]

    def post(self,request):
        serializer=TicketSerializer(data=request.data)
        if not serializer.is_valid():
            return Response({
                "data":None,
                "errors":serializer.errors,
                "status":400
            })
        result=create_ticket_service(serializer.validated_data,request.user)

        return return_response(result)
    
class TicketListView(APIView):
    permission_classes=[IsAuthenticated]

    def get(self,request):
        result=get_ticket_list_service(request)
        return return_response(result)

class TicketDetailView(APIView):
    permission_classes=[IsAuthenticated]
    def get(self,request,ticket_id):
        result=get_ticket_detail_service(ticket_id)
        return return_response(result)
    
class AcceptTicketView(APIView):
    permission_classes=[IsAuthenticated]

    def post(self,request,ticket_id):
        result=accept_ticket_service(ticket_id,request.user)
        return return_response(result)