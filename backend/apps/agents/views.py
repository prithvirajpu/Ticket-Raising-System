from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.pagination import PageNumberPagination
from rest_framework.generics import ListAPIView 
from rest_framework.permissions import IsAuthenticated
from apps.core_app.permissions import IsAdmin
from apps.core_app.constants import ApprovalStatus
from apps.core_app.utils import return_response
from apps.core_app.models import AgentApplication
from rest_framework.parsers import MultiPartParser, FormParser
from .services import (update_agent_profile_service,get_agent_ticket_requests_service,get_agent_ongoing_tickets_service,get_agent_ticket_detail_service,
                       agent_summary_service,fetch_fake_tickets_service,get_fake_ticket_detail_service,accept_ticket_service,reject_ticket_service,
                       verify_ticket_service,reset_training_ticket
)
from django.contrib.auth import get_user_model
import logging
logger=logging.getLogger(__name__)

User=get_user_model()

class UpdateAgentProfileView(APIView):
    permission_classes = [IsAuthenticated]

    def put(self, request):
        result=update_agent_profile_service(request.user,request.data,request.FILES)
        return return_response(result)
    
class AgentTicketRequestsView(APIView):
    permission_classes=[IsAuthenticated]

    def get(self,request):
        search=request.query_params.get('search','')
        sort=request.query_params.get('sort','newest')
        page=int(request.query_params.get('page',1))
        page_size=int(request.query_params.get('page_size',5))
        result=get_agent_ticket_requests_service(request.user,sort,search,page,page_size)
        return return_response(result)
    
class AgentOngoingTicketsView(APIView):
    permission_classes=[IsAuthenticated]

    def get(self,request):
        search=request.query_params.get('search','')
        sort=request.query_params.get('sort','newest')
        page = int(request.query_params.get('page', 1))
        page_size = int(request.query_params.get('page_size', 5))
        result=get_agent_ongoing_tickets_service(request.user,sort,search,page, page_size)
        return return_response(result)

class AgentTicketDetailView(APIView):
    permission_classes=[IsAuthenticated]

    def get(self,request,ticket_id):
        result=get_agent_ticket_detail_service(request,ticket_id)
        return return_response(result)
    
class AgentSummaryView(APIView):
    permission_classes= [IsAuthenticated]

    def get(self,request):
        result= agent_summary_service(request)
        return return_response(result)
    
class AgentFakeTicketsView(APIView):
    permission_classes= [IsAuthenticated]

    def get(self,request):
        result=fetch_fake_tickets_service(request.user)
        return return_response(result)
    
class AgentFakeTicketDetailView(APIView):
    permission_classes=[IsAuthenticated]

    def get(self,request,id):
        result=get_fake_ticket_detail_service(request.user,id)
        return return_response(result)
    
class AcceptTicketView(APIView):
    permission_classes=[IsAuthenticated]

    def post(self,request,ticket_id):
        result=accept_ticket_service(ticket_id,request.user)
        return return_response(result)
    
class RejectTicketView(APIView):
    permission_classes=[IsAuthenticated]

    def post(self,request,ticket_id):
        reason=request.data.get('reason','default')
        result=reject_ticket_service(ticket_id,request.user,reason)
        return return_response(result)
    
class VerifyTicketAPIView(APIView):
    permission_classes= [IsAuthenticated]

    def post(self,request):
        result= verify_ticket_service(request.data)
        return return_response(result)
    
class RetryTrainingAPIView(APIView):
    permission_classes=[IsAuthenticated]

    def post(self,request,ticket_id):
        logger.info('RETRY HIT--%s')
        result=reset_training_ticket(request,ticket_id)
        return return_response(result)