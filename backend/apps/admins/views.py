from rest_framework.views import APIView
from rest_framework.pagination import PageNumberPagination
from rest_framework.generics import ListAPIView 
from rest_framework.permissions import IsAuthenticated
from apps.core_app.permissions import IsAdmin
from apps.core_app.constants import ApprovalStatus
from apps.core_app.utils import return_response
from apps.core_app.models import AgentApplication
from rest_framework.parsers import MultiPartParser, FormParser
from .services import (approve_user_service,reject_user_service,
                       get_agent_application_detail_service,get_client_list_service,
                       get_agent_list_service,toggle_agent_status_service)
from .serializers import (UserApprovalSerializer)
from django.contrib.auth import get_user_model
import logging
logger=logging.getLogger(__name__)

User=get_user_model()

class PendingUsersPagination(PageNumberPagination):
    page_size = 10
    page_size_query_param = "page_size"
    max_page_size = 100

class PendingUsersView(ListAPIView):
    permission_classes = [IsAdmin]
    serializer_class = UserApprovalSerializer
    pagination_class = PendingUsersPagination

    def get_queryset(self):
        return AgentApplication.objects.filter(
            status=ApprovalStatus.PENDING
        ).order_by("-applied_at")
    
class AgentApplicationDetailView(APIView):
    permission_classes=[IsAdmin]

    def get(self,request,pk):
        result=get_agent_application_detail_service(pk)
        return return_response(result)
    
class ApproveUserView(APIView):
    permission_classes = [IsAdmin]

    def post(self, request, *args, **kwargs):
        user_id = kwargs.get('pk')
        role = request.data.get('role')
        result=approve_user_service(user_id,role)
        return return_response(result)
    
class RejectUserView(APIView):
    permission_classes=[IsAdmin]

    def post(self,request,*args,**kwargs):
        application_id =self.kwargs['pk']
        result=reject_user_service(application_id)
        return return_response(result)
    
class ClientListView(APIView):
    permission_classes = [IsAuthenticated, IsAdmin]

    def get(self, request):
        result=get_client_list_service(request)
        return return_response(result)
    
class AgentListView(APIView):
    permission_classes = [IsAuthenticated, IsAdmin]

    def get(self, request):
        result=get_agent_list_service(request)
        return return_response(result)
    
class ToggleAgentStatusView(APIView):
    permission_classes=[IsAdmin]

    def patch(self,request,agent_id):
        is_active=request.data.get('is_active')
        result=toggle_agent_status_service(agent_id,is_active)
        return return_response(result)
    