from django.utils import timezone
from datetime import timedelta
from django.contrib.auth.hashers import make_password
from django.db import transaction
import random
from rest_framework.views import APIView
from rest_framework.generics import ListAPIView
from core_app.permissions import IsAdmin
from core_app.constants import ApprovalStatus
from rest_framework.response import Response
from rest_framework import status
from .models import User
from core_app.constants import UserRole 
from core_app.models import EmailOTP,AgentApplication
from core_app.utils import generate_otp,send_otp_email
from rest_framework_simplejwt.tokens import RefreshToken
from .serializers import LoginSerializer,UserApprovalSerializer,ClientSignupSerializer,AgentSignupSerializer,VerifyOTPSerializer

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
        user=serializer.save()
        EmailOTP.objects.filter(email=email).delete()
        otp_code=generate_otp()
        print('otp_code',otp_code)
        EmailOTP.objects.create(email=email,otp=otp_code)
        send_otp_email(email,otp_code)
        return Response({'message':'OTP sent to you email'},
                        status=status.HTTP_200_OK)
    
class AgentSignupView(APIView):
    permission_classes=[]

    def post(self,request):
        serializer=AgentSignupSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        application=serializer.save()
        email=serializer.validated_data['email']
        otp=generate_otp()
        print(otp)
        EmailOTP.objects.create(email=application.email,otp=otp)
        send_otp_email(email,otp)
        return Response({'message':'Agent application submitted. Await admin approval'},
                        status=status.HTTP_201_CREATED)

class VerifyOTPView(APIView):
    permission_classes=[]

    def post(self,request):
        serializer=VerifyOTPSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        email=serializer.validated_data['email']
        otp=serializer.validated_data['otp']

        otp_obj=EmailOTP.objects.filter(email=email,otp=otp).first()
        if not otp_obj:
            return Response({'error':'Invalid OTP'},status=status.HTTP_400_BAD_REQUEST)
        if otp_obj.is_expired():
            otp_obj.delete()
            return Response({'error':'OTP expired'},status=status.HTTP_400_BAD_REQUEST)
        existing_user=User.objects.filter(email=email).first()
        if existing_user:
            if not existing_user.is_verified:
                existing_user.is_verified=True
                existing_user.is_active=True
                existing_user.save()
            otp_obj.delete()
            return Response({'message':'User email verified.'})
        application=AgentApplication.objects.filter(email=email).first()
        if application:
            if not application.email_verified:
                application.email_verified=True
                application.save()
            otp_obj.delete()
            return Response({'message':'Application email verified'})
        otp_obj.delete()
        return Response({'error':'Account not found'},status=status.HTTP_400_BAD_REQUEST)
    
class ResendOTPView(APIView):
    permission_classes = []

    def post(self, request):
        email = request.data.get('email')
        if not email:
            return Response(
                {'error': 'Email is required'},
                status=status.HTTP_400_BAD_REQUEST
            )
        otp_obj = EmailOTP.objects.filter(email=email).first()

        if otp_obj and otp_obj.created_at > timezone.now() - timedelta(minutes=1):
            return Response(
                {'error': 'If the email exists, OTP has been sent'},
                status=status.HTTP_429_TOO_MANY_REQUESTS
            )
        if otp_obj:
            otp_obj.delete()
        new_otp = generate_otp()
        print(new_otp)  
        EmailOTP.objects.create(email=email, otp=new_otp)
        send_otp_email(email, new_otp)
        return Response(
            {'message': 'OTP resent successfully'},
            status=status.HTTP_200_OK
        )

class ForgotPasswordView(APIView):
    permission_classes=[]

    def post(self,request):
        print('passing data',request.data)
        serializer=ClientSignupSerializer(data=request.data,partial=True)
        serializer.is_valid(raise_exception=True)
        email=serializer.validated_data['email']
        print('email is',email)
        if not User.objects.filter(email__iexact=email).exists():
            return Response({'error':'Email not found'},status=status.HTTP_400_BAD_REQUEST)
        EmailOTP.objects.filter(email=email).delete()
        otp=generate_otp()
        print(otp)
        EmailOTP.objects.create(email=email,otp=otp)
        send_otp_email(email,otp)
        print('email sent success')
        return Response({'message':"OTP sent successfully"})
        

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
