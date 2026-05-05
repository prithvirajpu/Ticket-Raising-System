from rest_framework.views import APIView
from core_app.permissions import IsAgent
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from core_app.utils import return_response
from tickets.serializer import TicketSerializer
from tickets.services import (create_ticket_service,get_ticket_list_service,get_ticket_detail_service,accept_ticket_service,reject_ticket_service,
                            get_agent_ticket_requests_service,get_agent_ticket_detail_service,get_agent_ongoing_tickets_service,resolve_ticket_service,
                            close_ticket_service,submit_review_service,escalate_ticket_service,get_profile_service,update_profile_service,
                            get_team_lead_tickets_service,get_manager_tickets_service,upload_client_doc_service,get_clients_with_documents,
                            get_client_documents,summarize_document_service,submit_summary_service,get_teamlead_summaries_service,generate_agent_summary_service,
                            submit_agent_summary_service,agent_summary_service,dashboard_service,generate_fake_ticket_service,fetch_fake_tickets_service,get_fake_ticket_detail_service)



# tickets/views/dev_auth.py

from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import AllowAny
from rest_framework import status

from django.contrib.auth import get_user_model
from rest_framework_simplejwt.tokens import RefreshToken

User = get_user_model()


@api_view(["POST"])
@permission_classes([AllowAny])
def dev_login(request):
    email = request.data.get("email")

    if not email:
        return Response({"error": "Email required"}, status=400)

    user = User.objects.filter(email=email).first()

    if not user:
        return Response({"error": "User not found"}, status=404)

    refresh = RefreshToken.for_user(user)

    return Response({
        "access": str(refresh.access_token),
        "refresh": str(refresh),
        "user_id": user.id,
        "email": user.email
    })

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
        search=request.query_params.get('search','')
        sort=request.query_params.get('sort','newest')
        page = int(request.query_params.get('page', 1))
        result=get_ticket_list_service(request,sort,search,page)
        return return_response(result)

class TicketDetailView(APIView):
    permission_classes=[IsAuthenticated]
    def get(self,request,ticket_id):
        result=get_ticket_detail_service(ticket_id,request)
        return return_response(result)
    
class TicketCloseView(APIView):
    permission_classes=[IsAuthenticated]
    def post(self,request,ticket_id):
        res=close_ticket_service(request.user,ticket_id)
        return return_response(res)
    
class SubmitReviewView(APIView):
    permission_classes=[IsAuthenticated]
    def post(self,request,ticket_id):
        rating=request.data.get('rating')
        review=request.data.get('review','')
        res=submit_review_service(request.user,ticket_id,rating,review)
        return return_response(res)
    
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

class AgentTicketRequestsView(APIView):
    permission_classes=[IsAuthenticated]

    def get(self,request):
        search=request.query_params.get('search','')
        sort=request.query_params.get('sort','newest')
        page=int(request.query_params.get('page',1))
        page_size=int(request.query_params.get('page_size',5))
        result=get_agent_ticket_requests_service(request.user,sort,search,page,page_size)
        return return_response(result)
    
class AgentTicketDetailView(APIView):
    permission_classes=[IsAuthenticated]

    def get(self,request,ticket_id):
        result=get_agent_ticket_detail_service(request,ticket_id)
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
    
class ResolveTicketView(APIView):
    permission_classes=[IsAuthenticated]

    def post(self,request,ticket_id):
        result=resolve_ticket_service(request.user,ticket_id)
        return return_response(result)

class EscalatedTicketView(APIView):
    permission_classes=[IsAuthenticated]

    def post(self,request,ticket_id):
        result= escalate_ticket_service(request.user,ticket_id)
        return return_response(result)

class UserProfileView(APIView):
    permission_classes=[IsAuthenticated]

    def get(self,request):
        result=get_profile_service(request.user)
        return return_response(result)

class UpdateProfileView(APIView):
    permission_classes= [IsAuthenticated]

    def put(self,request):
        result= update_profile_service(request.user,request.data)
        return return_response(result)

class TeamLeadTicketView(APIView):
    permission_classes=[IsAuthenticated]

    def get(self,request):
        result=get_team_lead_tickets_service(request.user)
        return return_response(result)
    
class ManagerTicketsView(APIView):
    permission_classes=[IsAuthenticated]

    def get(self,request):
        result=get_manager_tickets_service(request.user)
        return return_response(result)

class UploadDocView(APIView):
    permission_classes=[IsAuthenticated]

    def post(self,request):
        files=request.FILES
        if not files:
            return {
                'data':None,
                'errors':{'details':'No files uploaded'},
                'status':400
            }
        result=upload_client_doc_service(request.user,files)
        return return_response(result)
    
class ClientListWithDocsView(APIView):
    permission_classes=[IsAuthenticated]

    def get(self,request):
        result=get_clients_with_documents()
        return return_response(result)
    
class ClientDocumentsView(APIView):
    permission_classes=[IsAuthenticated]

    def get(self,request,client_id):
        result= get_client_documents(client_id)
        return return_response(result)

class SummarizeDocumentView(APIView):
    permission_classes= [IsAuthenticated]

    def post (self,request,doc_id):
        result= summarize_document_service(request.user,doc_id)
        return return_response(result)
    
class SubmitSummaryView(APIView):
    permission_classes=[IsAuthenticated]

    def post (self,request,doc_id):
        result= submit_summary_service(request,doc_id)
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
    
class AgentSummaryView(APIView):
    permission_classes= [IsAuthenticated]

    def get(self,request):
        result= agent_summary_service(request)
        return return_response(result)
    
class DashboardView(APIView):
    permission_classes=[IsAuthenticated]

    def get(self,request):
        role=request.user.role
        result=dashboard_service(request,role)
        return return_response(result)

    
class GenerateFakeTicketView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self,request):
        result=generate_fake_ticket_service(request)
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
    
from rest_framework.generics import CreateAPIView,ListAPIView
from tickets.serializer import TicketChatSerializer
from tickets.services import send_message_service,get_messages_service
class SendMessageView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request, ticket_id):
        message = request.data.get("message")

        result = send_message_service(
            user=request.user,
            ticket_id=ticket_id,
            message=message
        )

        return Response(result)

class TicketMessageView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request, ticket_id):
        result = get_messages_service(request.user, ticket_id)
        return Response(result)
