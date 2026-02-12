from rest_framework.views import APIView
from rest_framework.generics import ListAPIView
from core_app.permissions import IsAdmin
from core_app.constants import ApprovalStatus
from rest_framework.response import Response
from rest_framework import status
from .models import User
from core_app.models import EmailOTP
from core_app.utils import generate_otp,send_otp_email
from rest_framework_simplejwt.tokens import RefreshToken
from .serializers import LoginSerializer,UserApprovalSerializer,ClientSignupSerializer,AgentSignupSerializer

class LoginView(APIView):
    permission_classes=[]

    def post(self,request):
        serializer=LoginSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        user=serializer.validated_data['user']
        refresh=RefreshToken.for_user(user)
        if not user.is_verified:
            return Response({'detail':'email not verified'},status=status.HTTP_403_FORBIDDEN)

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
        user=serializer.save()
        otp_code=generate_otp()
        print('otp_code',otp_code)
        EmailOTP.objects.create(user=user,otp=otp_code)
        # send_otp_email(user,otp_code)
        return Response({'message':'OTP sent to you email'},
                        status=status.HTTP_201_CREATED)

class VerifyOTPView(APIView):
    permission_classes=[]

    def post(self,request):
        email=request.data.get('email')
        otp=request.data.get('otp')

        try:
            user=User.objects.get(email=email)
        except User.DoesNotExist:
            return Response({'error':'User not found'},status=status.HTTP_404_NOT_FOUND)
        otp_obj=EmailOTP.objects.filter(user=user).last()
        if not otp_obj:
            return Response({'error':'OTP not found'},status=status.HTTP_400_BAD_REQUEST)
        if otp_obj.is_expired():
            return Response({'error':'OTP expired'},status=status.HTTP_400_BAD_REQUEST)
        if otp!=otp_obj.otp:
            return Response({"error":'Invalid OTP'},status=status.HTTP_400_BAD_REQUEST)
        
        user.is_verified=True
        user.is_active=True
        user.save()
        otp_obj.delete()
        return Response({'message0':'Email verified successfully'})


class AgentSignupView(APIView):
    permission_classes=[]
    def post(self,request):
        serializer=AgentSignupSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response({'message':'Agent application submitted. Await admin approval'},
                        status=status.HTTP_201_CREATED)

    

class PendingUsersView(ListAPIView):
    permission_classes=[IsAdmin]
    serializer_class=UserApprovalSerializer

    def get_queryset(self):
        return User.objects.filter(approval_status=ApprovalStatus.PENDING)
    
class ApproveUserView(APIView):
    permission_classes=[IsAdmin]

    def post(self,request,*args,**kwargs):
        print("=== DEBUG ===")
        print("request.data:", request.data)
        user_id=kwargs.get('pk')
        try:
            user=User.objects.get(id=user_id)
        except User.DoesNotExist:
            return Response({
                'details':'User not found'},
                status=status.HTTP_404_NOT_FOUND)

        serializer=UserApprovalSerializer(user,data=request.data,partial=True)
        serializer.is_valid(raise_exception=True)
        serializer.save(approval_status=ApprovalStatus.APPROVED,is_active=True)

        return Response({
            "details":'User Approved Successfully'},
            status=status.HTTP_200_OK)

class RejectUserView(APIView):
    permission_classes=[IsAdmin]

    def post(self,request,*args,**kwargs):
        user_id=self.kwargs['pk']
        try:
            user=User.objects.get(id=user_id)
        except User.DoesNotExist:
            return Response({
                "details":'User not found'},
                status=status.HTTP_404_NOT_FOUND)
        user.approval_status=ApprovalStatus.REJECTED
        user.is_active=False
        user.save()
        return Response({'details':'User rejected'}
                        ,status=status.HTTP_200_OK)
