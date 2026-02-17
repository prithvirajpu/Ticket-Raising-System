from django.utils import timezone
from datetime import timedelta
from django.contrib.auth.hashers import make_password
from django.db import transaction
import random
from rest_framework.views import APIView
from rest_framework.generics import ListAPIView
from rest_framework.permissions import IsAuthenticated
from core_app.permissions import IsAdmin
from core_app.constants import ApprovalStatus
from rest_framework.response import Response
from rest_framework import status
from .models import User
from core_app.constants import UserRole 
from core_app.models import EmailOTP,AgentApplication,AgentCertificate
from core_app.utils import generate_otp,send_otp_email
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework.parsers import MultiPartParser, FormParser
from core_app.utils import generate_jwt_token   
from google.oauth2 import id_token as google_id_token
from google.auth.transport import requests
from django.conf import settings 
from .serializers import (
    LoginSerializer,UserApprovalSerializer,ClientSignupSerializer,AgentSignupSerializer,
    VerifyOTPSerializer,ForgotPasswordSerializer,ResetPasswordSerializer)

class LoginView(APIView):
    permission_classes=[]

    def post(self,request):
        serializer=LoginSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        user=serializer.validated_data['user']
        refresh=RefreshToken.for_user(user)
        if not user.is_verified:
            return Response({'detail':'email not verified'},status=status.HTTP_403_FORBIDDEN)
        if user.approval_status=='PENDING':
            return Response({'detail':'Waiting for the Admin Approval'},status=status.HTTP_400_BAD_REQUEST)

        return Response({
            'access':str(refresh.access_token),
            'refresh':str(refresh),
            'role':user.role,
        },status=status.HTTP_200_OK)
    
# class LogoutView(APIView):
#     def post(self,request):
#         response=Response({'detail':'Logged Out'})
#         response.delete_cookie('access')
#         response.delete_cookie('refresh')
#         return response


class ClientSignupView(APIView):
    permission_classes=[]
    
    def post(self,request):
        serializer=ClientSignupSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        email=serializer.validated_data['email']
        if User.objects.filter(email=email).exists():
            return Response({'error': 'Email already registered'}, status=status.HTTP_400_BAD_REQUEST)
        serializer.save()
        EmailOTP.objects.filter(email=email,purpose='SIGNUP').delete()
        otp_code=generate_otp()
        print('otp_code',otp_code)
        otp_obj=EmailOTP.objects.create(email=email,otp=otp_code,purpose='SIGNUP')
        expiry_time=otp_obj.created_at+timezone.timedelta(minutes=1)
        send_otp_email(email,otp_code)
        return Response({'message':'OTP sent to you email',"expires_at":expiry_time.isoformat()},
                        status=status.HTTP_201_CREATED)

class AgentSignupView(APIView):
    permission_classes = []
    parser_classes = (MultiPartParser, FormParser)

    def post(self, request):
        print("=== FULL REQUEST DATA ===", dict(request.data))
        print("=== FILES ===", [f.name for f in request.FILES.getlist('certificates')])
        email = request.data.get("email")
        if not email:
            return Response({"error": "Email is required."}, status=status.HTTP_400_BAD_REQUEST)

        # Copy data and attach files
        data = request.data.copy()
        resume = request.FILES.get("resume")
        certificates = request.FILES.getlist("certificates")
        if resume:
            data["resume"] = resume
        if certificates:
            data.setlist("certificates", certificates)

        # Check if agent exists
        agent = AgentApplication.objects.filter(email=email).first()
        created = False

        if agent:
            # Update existing agent partially
            serializer = AgentSignupSerializer(agent, data=data, partial=True)
            print("=== IS VALID ===", serializer.is_valid())
            print("=== ERRORS ===", serializer.errors)  
        else:
            # Create new agent
            serializer = AgentSignupSerializer(data=data)
            print("=== IS VALID ===", serializer.is_valid())
            print("=== ERRORS ===", serializer.errors)  

        # Validate serializer
        if not serializer.is_valid():
            print("=== DETAILED ERRORS ===", serializer.errors)
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        # Save (certificates are handled inside serializer)
        agent = serializer.save()
        created = agent is not None and not agent.status == "PENDING"

        # Generate OTP
        EmailOTP.objects.filter(email=email, purpose="AGENT").delete()
        otp = generate_otp()
        print("Generated OTP:", otp)
        otp_obj = EmailOTP.objects.create(email=email, otp=otp, is_verified=False, purpose="AGENT")
        expiry_time = otp_obj.created_at + timezone.timedelta(minutes=1)
        send_otp_email(email, otp)

        message = "Agent application submitted. OTP sent to email for verification."
        if not created:
            message = "Existing agent found. OTP resent for email verification."

        return Response(
            {
                "message": message,
                "expires_at": expiry_time.isoformat()
            },
            status=status.HTTP_201_CREATED
        )

class VerifyOTPView(APIView):
    permission_classes = []

    def post(self, request):
        serializer = VerifyOTPSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        email = serializer.validated_data['email']
        otp = serializer.validated_data['otp']
        purpose = serializer.validated_data.get('purpose', 'SIGNUP')

        otp_obj = EmailOTP.objects.filter(
            email=email,
            otp=otp,
            is_verified=False,
            purpose=purpose
        ).first()

        if not otp_obj:
            return Response(
                {'error': 'Invalid OTP'},
                status=status.HTTP_400_BAD_REQUEST
            )

        if otp_obj.is_expired():
            otp_obj.delete()
            return Response(
                {'error': 'OTP expired'},
                status=status.HTTP_400_BAD_REQUEST
            )
        otp_obj.is_verified = True
        otp_obj.save()
        if purpose == 'RESET':
            return Response({'message': 'OTP verified for password reset'})

        if purpose == 'SIGNUP':
            user = User.objects.filter(email=email).first()
            if user:
                user.is_verified = True
                user.is_active = True
                user.save()
                otp_obj.delete()
                return Response({'message': 'User email verified'})

        if purpose == 'AGENT':
            application = AgentApplication.objects.filter(email=email).first()
            if application:
                application.email_verified = True
                application.save()
                otp_obj.delete()
                return Response({'message': 'Application email verified'})

        return Response(
            {'error': 'Invalid verification flow'},
            status=status.HTTP_400_BAD_REQUEST
        )
class ResetPasswordView(APIView):
    permission_classes = []

    def post(self, request):
        serializer = ResetPasswordSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        email = serializer.validated_data['email']
        new_password = serializer.validated_data['new_password']

        user = User.objects.filter(email=email).first()
        if not user:
            return Response({'error': 'User not found'},status=status.HTTP_404_NOT_FOUND)
        otp_obj = EmailOTP.objects.filter(email=email,purpose='RESET',is_verified=True).first()
        if otp_obj.is_expired():
            otp_obj.delete()
            return Response(
                {'error': 'OTP expired'},
                status=status.HTTP_400_BAD_REQUEST
            )
        if not otp_obj:
            return Response({'error': 'OTP not verified'},status=status.HTTP_400_BAD_REQUEST)
        user.set_password(new_password)
        user.save()
        otp_obj.delete()
        return Response({'message': 'Password reset successful'},status=status.HTTP_200_OK)
    
class ResendOTPView(APIView):
    permission_classes = []

    def post(self, request):
        email = request.data.get('email')
        purpose = request.data.get('purpose')
        if not email:
            return Response(
                {'error': 'Email is required'},
                status=status.HTTP_400_BAD_REQUEST
            )
        if not email or not purpose:
            return Response(
                {'error': 'Email and purpose are required'},
                status=status.HTTP_400_BAD_REQUEST
            )
        otp_obj = EmailOTP.objects.filter(email=email,purpose=purpose).first()

        if otp_obj and otp_obj.created_at > timezone.now() - timedelta(minutes=1):
            return Response(
                {'error': 'If the email exists, OTP has been sent'},
                status=status.HTTP_429_TOO_MANY_REQUESTS
            )
        if otp_obj:
            otp_obj.delete()
        new_otp = generate_otp()
        print(new_otp)  
        otp_obj=EmailOTP.objects.create(email=email, otp=new_otp,purpose=purpose)
        expiry_time=otp_obj.created_at+timezone.timedelta(minutes=1)
        send_otp_email(email, new_otp)
        return Response(
            {'message': 'OTP resent successfully',"expires_at":expiry_time.isoformat()},
            status=status.HTTP_200_OK
        )

class ForgotPasswordView(APIView):
    permission_classes=[]

    def post(self,request):
        print('passing data',request.data)
        serializer=ForgotPasswordSerializer(data=request.data,partial=True)
        serializer.is_valid(raise_exception=True)
        email=serializer.validated_data['email']
        print('email is',email)
        if not User.objects.filter(email__iexact=email).exists():
            return Response({'error':'Email not found'},status=status.HTTP_400_BAD_REQUEST)
        EmailOTP.objects.filter(email=email, purpose='RESET').delete()
        otp=generate_otp()
        print(otp)
        otp_obj=EmailOTP.objects.create(email=email,otp=otp,purpose='RESET')
        expiry_time=otp_obj.created_at+timezone.timedelta(minutes=1)
        send_otp_email(email,otp)
        print('email sent success')
        return Response({'message':"OTP sent successfully",
                         "expires_at":expiry_time.isoformat()})
        

class PendingUsersView(ListAPIView):
    permission_classes=[IsAdmin]
    serializer_class=UserApprovalSerializer

    def get_queryset(self):
        return AgentApplication.objects.filter(status='PENDING')
    
class ApproveUserView(APIView):
    permission_classes=[IsAdmin]

    def post(self,request,*args,**kwargs):
        user_id=kwargs.get('pk')
        try:
            agent=AgentApplication.objects.get(id=user_id,status='PENDING')
        except AgentApplication.DoesNotExist:
            return Response({
                'details':'Agent not found'},
                status=status.HTTP_404_NOT_FOUND)
        role=request.data.get('role')
        if role not in [UserRole.AGENT, UserRole.MANAGER, UserRole.TEAM_LEAD]:
            return Response({'error': 'Invalid role'}, status=400)
        user=User.objects.create(email=agent.email,name=agent.full_name,phone=agent.phone,role=role,approval_status=ApprovalStatus.APPROVED,
                                 is_active=True,is_verified=agent.email_verified,password=agent.password)
        agent.status="APPROVED"
        agent.save()
        
        return Response({
            "details":'Agent request approved as {role}.'},
            status=status.HTTP_200_OK)

class RejectUserView(APIView):
    permission_classes=[IsAdmin]

    def post(self,request,*args,**kwargs):
        user_id=self.kwargs['pk']
        try:
            agent=AgentApplication.objects.get(id=user_id)
        except AgentApplication.DoesNotExist:
            return Response({
                "details":'User not found'},
                status=status.HTTP_404_NOT_FOUND)
        agent.status='REJECTED'
        agent.is_active=False
        agent.save(update_fields=['status','is_active'])
        return Response({'details':'User rejected'}
                        ,status=status.HTTP_200_OK)

class AgentApplicationDetailView(APIView):
    permission_classes=[IsAdmin]

    def get(self,request,pk):
        print('pk',pk)
        try:
            agent=AgentApplication.objects.get(id=pk)
        except AgentApplication.DoesNotExist:
            return Response({'error':'Agent not found'},status=status.HTTP_404_NOT_FOUND)
        data = {
            "id": agent.id,
            "full_name": agent.full_name,
            "email": agent.email,
            "phone": agent.phone,
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
            return Response(
                {"error": "Missing token"},
                status=status.HTTP_400_BAD_REQUEST
            )

        try:
            # Verify Google token
            idinfo = google_id_token.verify_oauth2_token(
                token,
                requests.Request(),
                settings.GOOGLE_CLIENT_ID
            )

            email = idinfo.get("email")

            if not email:
                return Response(
                    {"error": "Unable to fetch email from Google."},
                    status=status.HTTP_400_BAD_REQUEST
                )

            # ====================================================
            # 🔥 LOGIN FLOW (No role provided)
            # ====================================================
            if not role:
                user = User.objects.filter(email=email).first()

                if not user:
                    return Response(
                        {"error": "Account not found. Please sign up first."},
                        status=status.HTTP_400_BAD_REQUEST
                    )

            # ====================================================
            # 🔥 SIGNUP FLOW (Role provided)
            # ====================================================
            else:

                if role == "CLIENT":

                    user, created = User.objects.get_or_create(
                        email=email,
                        defaults={
                            "role": "CLIENT",
                            "approval_status": "APPROVED",
                            "profile_completed": False,
                            "is_active": True,
                            "is_verified": True,
                        },
                    )

                elif role == "AGENT":

                    user, created = User.objects.get_or_create(
                        email=email,
                        defaults={
                            "role": "AGENT",
                            "approval_status": "PENDING",
                            "profile_completed": False,
                            "is_active": True,
                            "is_verified": True,
                        },
                    )

                    AgentApplication.objects.get_or_create(
                        email=email,
                        defaults={
                            "status": "PENDING",
                            "email_verified": True,
                        },
                    )

                else:
                    return Response(
                        {"error": "Invalid role"},
                        status=status.HTTP_400_BAD_REQUEST
                    )

                # 🚨 Prevent role switching
                if not created and user.role != role:
                    return Response(
                        {"error": f"Account already exists as {user.role}"},
                        status=status.HTTP_400_BAD_REQUEST
                    )

            # ====================================================
            # Generate JWT
            # ====================================================
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
            return Response(
                {"error": "Invalid Google token"},
                status=status.HTTP_400_BAD_REQUEST
            )

class UpdateClientProfileView(APIView):
    permission_classes=[IsAuthenticated]

    def put(self,request):
        user=request.user
        user.company_name=request.data.get('company_name')
        user.business_type=request.data.get('business_type')
        user.phone=request.data.get('phone')
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
            AgentCertificate.objects.create(
                agent=user,
                file=cert
            )

        return Response({"message": "Profile completed",
                         "status": agent_app.status,})
