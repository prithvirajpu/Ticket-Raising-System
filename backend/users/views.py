from rest_framework.views import APIView
from rest_framework.pagination import PageNumberPagination
from rest_framework.generics import ListAPIView 
from rest_framework.permissions import IsAuthenticated
from core_app.permissions import IsAdmin
from core_app.constants import ApprovalStatus
from rest_framework.response import Response
from rest_framework import status
from .models import User
from core_app.constants import UserRole 
from core_app.utils import return_response
from core_app.models import AgentApplication
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework.parsers import MultiPartParser, FormParser
from .services import (verify_otp_service,agent_signup_service,reset_password_service,resend_otp_service,update_client_profile_service,
                       check_user_email_exists,forgot_password_service,approve_user_service,reject_user_service,update_agent_profile_service,
                       client_signup_service,get_agent_application_detail_service,google_client_auth_service,get_client_list_service,
                       get_agent_list_service,login_service)
from .serializers import (
    LoginSerializer,UserApprovalSerializer,ClientSignupSerializer,
    VerifyOTPSerializer,ForgotPasswordSerializer,ResetPasswordSerializer)
import logging
logger=logging.getLogger(__name__)

class LoginView(APIView):
    permission_classes=[]

    def post(self,request):
        serializer=LoginSerializer(data=request.data,context={'request':request})
        serializer.is_valid(raise_exception=True)

        user=serializer.validated_data['user']
        result=login_service(user)
        return return_response(result)
    
class CheckUserExistsView(APIView):
    permission_classes=[]
    
    def post(self,request):
        email=request.data.get('email')
        result=check_user_email_exists(email)

        return return_response(result)
    
class ClientSignupView(APIView):
    permission_classes=[]
    
    def post(self,request):
        serializer=ClientSignupSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        result=client_signup_service(serializer)
        return return_response(result)
    
class AgentSignupView(APIView):
    permission_classes = []
    parser_classes = (MultiPartParser, FormParser)

    def post(self, request):
        result=agent_signup_service(request.data)
        return return_response(result)

class VerifyOTPView(APIView):
    permission_classes = []

    def post(self, request):
        serializer = VerifyOTPSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        email = serializer.validated_data["email"]
        otp = serializer.validated_data["otp"]
        purpose = serializer.validated_data.get("purpose", "SIGNUP")

        result = verify_otp_service(email, otp, purpose)

        return return_response(result)
    
class ResetPasswordView(APIView):
    permission_classes = []

    def post(self, request):
        serializer = ResetPasswordSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        reset_token=serializer.validated_data['reset_token']
        new_password = serializer.validated_data['new_password']

        result=reset_password_service(reset_token,new_password)
        return return_response(result)
    
class ResendOTPView(APIView):
    permission_classes = []

    def post(self, request):
        email = request.data.get('email')
        purpose = request.data.get('purpose')
        
        result=resend_otp_service(email,purpose)
        return return_response(result)

class ForgotPasswordView(APIView):
    permission_classes = []

    def post(self, request):
        serializer = ForgotPasswordSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        email = serializer.validated_data['email']
        result=forgot_password_service(email)
        return return_response(result)
        
        
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

class AgentApplicationDetailView(APIView):
    permission_classes=[IsAdmin]

    def get(self,request,pk):
        result=get_agent_application_detail_service(pk)
        return return_response(result)
    
class GoogleClientAuthView(APIView):
    permission_classes = []

    def post(self, request):
        token = request.data.get("id_token")
        role = request.data.get("role")  
        result=google_client_auth_service(token,role)
        return return_response(result)


class UpdateClientProfileView(APIView):
    permission_classes=[IsAuthenticated]

    def put(self,request):
        result=update_client_profile_service(request.user,request.data)
        return return_response(result)

    
class UpdateAgentProfileView(APIView):
    permission_classes = [IsAuthenticated]

    def put(self, request):
        result=update_agent_profile_service(request.user,request.data,request.FILES)
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
    