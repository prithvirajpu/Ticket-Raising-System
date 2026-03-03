from django.utils import timezone
from datetime import timedelta
from django.contrib.auth.hashers import make_password
from django.db import transaction
import secrets
from rest_framework.views import APIView
from rest_framework.pagination import PageNumberPagination
from rest_framework.generics import ListAPIView 
from rest_framework.permissions import IsAuthenticated
from core_app.permissions import IsAdmin
from core_app.constants import ApprovalStatus
from rest_framework.response import Response
from rest_framework import status
from .models import User,PasswordResetToken
from core_app.constants import UserRole 
from core_app.models import EmailOTP,AgentApplication,AgentCertificate
from core_app.utils import generate_otp,send_otp_email
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework.parsers import MultiPartParser, FormParser
from core_app.utils import generate_jwt_token   
from google.oauth2 import id_token as google_id_token
from google.auth.transport import requests
from django.conf import settings 
from .services import verify_otp_service
from .serializers import (
    LoginSerializer,UserApprovalSerializer,ClientSignupSerializer,AgentSignupSerializer,
    VerifyOTPSerializer,ForgotPasswordSerializer,ResetPasswordSerializer)
import logging
logger=logging.getLogger(__name__)

class LoginView(APIView):
    permission_classes=[]

    def post(self,request):
        serializer=LoginSerializer(data=request.data,context={'request':request})
        serializer.is_valid(raise_exception=True)

        user=serializer.validated_data['user']
        refresh=RefreshToken.for_user(user)
        return Response({
            'access':str(refresh.access_token),
            'refresh':str(refresh),
            'role':user.role,
        },status=status.HTTP_200_OK)
    
class CheckUserExistsView(APIView):
    permission_classes=[]
    
    def post(self,request):
        email=request.data.get('email')
        errors={}
        if email and User.objects.filter(email=email).exists():
            errors['email']='Email already exists'
        if errors:
            return Response(errors,status=status.HTTP_400_BAD_REQUEST)
        return Response({'message':'Available'})

class ClientSignupView(APIView):
    permission_classes=[]
    
    def post(self,request):
        serializer=ClientSignupSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        email=serializer.validated_data['email']
        serializer.save()

        EmailOTP.objects.filter(email=email,purpose='SIGNUP').delete()
        otp_code=generate_otp()
        otp_obj=EmailOTP.objects.create(email=email,otp=otp_code,purpose='SIGNUP')
        expiry_time=otp_obj.created_at+timedelta(minutes=1)
        send_otp_email(email,otp_code)

        return Response({'message':'OTP sent to you email',"expires_at":expiry_time.isoformat()},
                        status=status.HTTP_201_CREATED)

class AgentSignupView(APIView):
    permission_classes = []
    parser_classes = (MultiPartParser, FormParser)

    def post(self, request):
        email = request.data.get("email")
        if not email:
            return Response({"error": "Email is required."}, status=status.HTTP_400_BAD_REQUEST)

        existing_agent = AgentApplication.objects.filter(email=email).first()

        if existing_agent:
            serializer = AgentSignupSerializer(existing_agent, data=request.data, partial=True)
        else:
            serializer = AgentSignupSerializer(data=request.data) 
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        agent = serializer.save()
        is_new=existing_agent is None

        EmailOTP.objects.filter(email=email, purpose="AGENT").delete()
        otp = generate_otp()
        EmailOTP.objects.create(email=email, otp=otp, is_verified=False, purpose="AGENT")
        expiry_time = timezone.now() + timedelta(minutes=1)
        send_otp_email(email, otp)

        if is_new:
            message = "Agent application submitted. OTP sent to email for verification."
            response_status =status.HTTP_201_CREATED
        else:
            message="Existing agent found. OTP resent for email verification."
            response_status=status.HTTP_200_OK

        return Response({"message": message,
                        "expires_at": expiry_time.isoformat()},status=response_status)

class VerifyOTPView(APIView):
    permission_classes = []

    def post(self, request):
        serializer = VerifyOTPSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        email = serializer.validated_data["email"]
        otp = serializer.validated_data["otp"]
        purpose = serializer.validated_data.get("purpose", "SIGNUP")

        try:
            result = verify_otp_service(email, otp, purpose)
            return Response(
                {"message": result["message"], **({ "reset_token": result.get("reset_token") } if result.get("reset_token") else {})},
                status=result["status"]
            )

        except ValueError as e:
            return Response(
                {"error": str(e)},
                status=status.HTTP_400_BAD_REQUEST
            )
    
class ResetPasswordView(APIView):
    permission_classes = []

    def post(self, request):
        serializer = ResetPasswordSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        reset_token=serializer.validated_data['reset_token']
        new_password = serializer.validated_data['new_password']

        token_obj=PasswordResetToken.objects.filter(token=reset_token).first()

        if not token_obj:
            return Response({'error': 'Invalid reset token'},status=status.HTTP_404_NOT_FOUND)
        
        if token_obj.is_expired():
            token_obj.delete()
            return Response( {'error': 'OTP expired'}, status=status.HTTP_400_BAD_REQUEST)
        user=token_obj.user
        if user.check_password(new_password):
            return Response({'error':'New password cannot be the same as the old password'}
                            ,status=status.HTTP_400_BAD_REQUEST)
        
        user.set_password(new_password)
        user.save()
        token_obj.delete()
        return Response({'message': 'Password reset successful'},status=status.HTTP_200_OK)
    
class ResendOTPView(APIView):
    permission_classes = []

    def post(self, request):
        email = request.data.get('email')
        purpose = request.data.get('purpose')
        
        if not email or not purpose:
            return Response( {'error': 'Email is required '}, status=status.HTTP_400_BAD_REQUEST)
        recent_otp=EmailOTP.objects.filter(email=email,purpose=purpose,created_at__gte=timezone.now()-timedelta(minutes=1)).first()
        
        if recent_otp:
            return Response({'error':'Please wait before requesting another OTP'},status=status.HTTP_429_TOO_MANY_REQUESTS)
        EmailOTP.objects.filter(email=email,purpose=purpose).delete()

        new_otp = generate_otp()

        EmailOTP.objects.create(email=email, otp=new_otp,purpose=purpose)
        expiry_time=timezone.now()+timedelta(minutes=1)
        send_otp_email(email, new_otp)
        return Response(
            {'message': 'OTP resent successfully',
             "expires_at":expiry_time.isoformat()},status=status.HTTP_200_OK)


class ForgotPasswordView(APIView):
    permission_classes = []

    def post(self, request):
        serializer = ForgotPasswordSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        email = serializer.validated_data['email']

        user = User.objects.filter(email__iexact=email).first()
        if not user:
            return Response(
                {"error": "User not found"},
                status=status.HTTP_400_BAD_REQUEST
            )

        recent_otp = EmailOTP.objects.filter(
            email=email,
            purpose='RESET',
            created_at__gte=timezone.now() - timedelta(minutes=1)
        ).first()

        if recent_otp:
            expiry_time = recent_otp.created_at + timedelta(minutes=1)
        else:
            EmailOTP.objects.filter(
                email=email,
                purpose='RESET'
            ).delete()

            otp = generate_otp()

            otp_obj = EmailOTP.objects.create(
                email=email,
                otp=otp,
                purpose='RESET'
            )

            send_otp_email(email, otp)
            expiry_time = timezone.now() + timedelta(minutes=1)

        return Response(
            {
                "message": "OTP sent successfully",
                "expires_at": expiry_time.isoformat()
            },
            status=status.HTTP_200_OK
        )
        
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
            status="PENDING"
        ).order_by("-applied_at")
    
class ApproveUserView(APIView):
    permission_classes = [IsAdmin]

    def post(self, request, *args, **kwargs):
        user_id = kwargs.get('pk')

        try:
            agent = AgentApplication.objects.get(
                id=user_id,
                status='PENDING'
            )
        except AgentApplication.DoesNotExist:
            return Response(
                {'details': 'Agent not found'},
                status=status.HTTP_404_NOT_FOUND
            )

        role = request.data.get('role')

        if role not in [UserRole.AGENT, UserRole.MANAGER, UserRole.TEAM_LEAD]:
            return Response(
                {'error': 'Invalid role'},
                status=status.HTTP_400_BAD_REQUEST
            )

        user = User.objects.filter(email=agent.email).first()

        if user:
            user.role = role
            user.approval_status = ApprovalStatus.APPROVED
            user.is_active = True
            user.is_verified = agent.email_verified
            user.save()
        else:
            user = User.objects.create(
                email=agent.email,
                name=agent.full_name,
                phone=agent.phone,
                role=role,
                approval_status=ApprovalStatus.APPROVED,
                is_active=True,
                is_verified=agent.email_verified,
                password=agent.password  
            )

        agent.status = "APPROVED"
        agent.save()

        return Response(
            {"details": f"Agent request approved as {role}."},
            status=status.HTTP_200_OK
        )

class RejectUserView(APIView):
    permission_classes=[IsAdmin]

    def post(self,request,*args,**kwargs):
        application_id =self.kwargs['pk']
        try:
            agent=AgentApplication.objects.get(id=application_id)

        except AgentApplication.DoesNotExist:
            return Response({
                "details":'User not found'},
                status=status.HTTP_404_NOT_FOUND)
        try:
            user=User.objects.get(email=agent.email)
        except User.DoesNotExist:
            return Response({'details':'User not found with this email'})
        
        agent.status='REJECTED'
        agent.is_active=False
        agent.save(update_fields=['status','is_active'])
        user.approval_status='REJECTED'
        user.save(update_fields=['approval_status'])
        return Response({'details':'User rejected'},status=status.HTTP_200_OK)

class AgentApplicationDetailView(APIView):
    permission_classes=[IsAdmin]

    def get(self,request,pk):
        try:
            agent=AgentApplication.objects.get(id=pk)
        except AgentApplication.DoesNotExist:
            return Response({'error':'Agent not found'},status=status.HTTP_404_NOT_FOUND)
        data = {
            "id": agent.id,
            "full_name": agent.full_name,
            "email": agent.email,
            "phone": agent.phone,
            "skills": agent.skills,
            "status": agent.status,
            "resume": agent.resume.url if agent.resume else None,
            "certificates": [cert.file.url for cert in agent.certificates.all()],
            "created_at": agent.applied_at,
        }
        print(data)
        return Response(data, status=status.HTTP_200_OK)
    
class GoogleClientAuthView(APIView):
    permission_classes = []

    def post(self, request):
        token = request.data.get("id_token")
        role = request.data.get("role")  

        if not token:
            return Response( {"error": "Missing token"}, status=status.HTTP_400_BAD_REQUEST)

        try:
            idinfo = google_id_token.verify_oauth2_token( token, requests.Request(), settings.GOOGLE_CLIENT_ID)
            email = idinfo.get("email")
            
            if not email:
                return Response( {"error": "Unable to fetch email from Google."}, status=status.HTTP_400_BAD_REQUEST)
            
            user=User.objects.filter(email=email).first()
            if user and user.approval_status=='REJECTED':
                return Response({"error":'Agent application is rejected.'},status=status.HTTP_400_BAD_REQUEST)
            if not role:
                if not user:
                    return Response( {"error": "Account not found. Please sign up first."}, status=status.HTTP_400_BAD_REQUEST)
            else:
                if role == "CLIENT":
                    user, created = User.objects.get_or_create(
                        email=email,
                        defaults={"role": "CLIENT","approval_status": "APPROVED","profile_completed": False,"is_active": True,"is_verified": True,},)
                elif role == "AGENT":
                    user, created = User.objects.get_or_create( email=email, defaults={ "role": "AGENT", "approval_status": "PENDING",
                                                            "profile_completed": False, "is_active": True, "is_verified": True,},)
                    AgentApplication.objects.get_or_create(email=email,defaults={"status": "PENDING","email_verified": True,},)
                else:
                    return Response({"error": "Invalid role"},status=status.HTTP_400_BAD_REQUEST)

                if not created and user.role != role:
                    return Response(
                        {"error": f"Account already exists as {user.role}"},
                        status=status.HTTP_400_BAD_REQUEST
                    )
            jwt_token = generate_jwt_token(user)

            return Response({
                "message": "Login successful",
                "user_id": user.id,
                "email": user.email,
                "role": user.role,
                "approval_status": user.approval_status,
                "profile_completed": user.profile_completed,
                "access": jwt_token["access"],
                "refresh": jwt_token["refresh"],
            }, status=status.HTTP_200_OK)

        except ValueError:
            return Response({"error": "Invalid Google token"},status=status.HTTP_400_BAD_REQUEST)

class UpdateClientProfileView(APIView):
    permission_classes=[IsAuthenticated]

    def put(self,request):
        user=request.user
        user.company_name=request.data.get('company_name')
        user.business_type=request.data.get('business_type')
        user.phone=request.data.get('phone')
        user.profile_completed=True
        user.save()
        return Response({'message':'Profile updated'})
    
class UpdateAgentProfileView(APIView):
    permission_classes = [IsAuthenticated]

    def put(self, request):
        user = request.user
        agent_app = AgentApplication.objects.get(email=user.email)

        user.phone = request.data.get("phone")
        user.skills = request.data.get("skills")
        user.resume = request.FILES.get("resume")
        user.profile_completed=True
        user.save()
        certificates = request.FILES.getlist("certificates")

        for cert in certificates:
            AgentCertificate.objects.create(agent=agent_app,file=cert)
        return Response({"message": "Profile completed", "status": agent_app.status,})

class ClientListView(APIView):
    permission_classes = [IsAuthenticated, IsAdmin]

    def get(self, request):
        clients = User.objects.filter(role="CLIENT").order_by("-created_at")
        paginator=PageNumberPagination()
        paginator.page_size=10
        page=paginator.paginate_queryset(clients,request)

        total_clients = clients.count()
        pending_clients = clients.filter(is_active=False).count()

        data = []
        for client in page:
            data.append({
                "id": client.id,
                "name": client.name,
                "email": client.email,
                "phone": client.phone,
                "business_type": client.business_type,
                "is_active": client.is_active,
                "date_joined": client.created_at
            })

        return paginator.get_paginated_response({
            "total_clients": total_clients,
            "pending_clients": pending_clients,
            "clients": data
        })


class AgentListView(APIView):
    permission_classes = [IsAuthenticated, IsAdmin]

    def get(self, request):
        agents = User.objects.filter(role__in=[UserRole.AGENT,UserRole.TEAM_LEAD,UserRole.MANAGER],approval_status=ApprovalStatus.APPROVED).order_by("-created_at")
        paginator=PageNumberPagination()
        paginator.page_size=1

        page=paginator.paginate_queryset(agents,request)

        total_agents = agents.count()
        active_agents = agents.filter(approval_status=ApprovalStatus.APPROVED).count()
        inactive_agents = agents.filter(approval_status=ApprovalStatus.PENDING).count()

        data = []

        for agent in page:
            data.append({
                "id": agent.id,
                "name": agent.name,
                "email": agent.email,
                "role": agent.role,
                "phone": agent.phone,
                "is_active": agent.is_active,
                "date_joined": agent.created_at,
            })

        return paginator.get_paginated_response({
            "total_agents": total_agents,
            "active_agents": active_agents,
            "inactive_agents": inactive_agents,
            "agents": data
        })
    