from rest_framework.views import APIView
from rest_framework.permissions import IsAuthenticated
from apps.core_app.utils import return_response
from .services import (get_team_lead_tickets_service,get_teamlead_summaries_service,generate_agent_summary_service,submit_agent_summary_service,
                       generate_fake_ticket_service)

# Create your views here.

class TeamLeadTicketView(APIView):
    permission_classes=[IsAuthenticated]

    def get(self,request):
        result=get_team_lead_tickets_service(request.user)
        return return_response(result)
    
class TeamLeadSummaryView(APIView):
    permission_classes =[IsAuthenticated]

    def get(self,request):
        result= get_teamlead_summaries_service(request)
        return return_response(result)
    
class SummaryTeamLeadView(APIView):
    permission_classes= [IsAuthenticated]

    def post(self,request,summary_id):
        result= generate_agent_summary_service(request,summary_id)
        return return_response(result)
    
class SubmitSummaryToAgentsView(APIView):
    permission_classes=[IsAuthenticated]
    
    def post(self,request,summary_id):
        result=submit_agent_summary_service(request,summary_id)
        return return_response(result)
    
class GenerateFakeTicketView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self,request):
        result=generate_fake_ticket_service(request)
        return return_response(result)