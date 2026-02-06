from rest_framework.views import APIView
from rest_framework.generics import ListAPIView
from core_app.permissions import IsAdmin
from core_app.constants import ApprovalStatus
from rest_framework.response import Response
from rest_framework import status
from .models import User
from rest_framework_simplejwt.tokens import RefreshToken
from .serializers import LoginSerializer,UserApprovalSerializer

class LoginView(APIView):

    def post(self,request):
        serializer=LoginSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        user=serializer.validated_data['user']
        refresh=RefreshToken.for_user(user)

        response=Response({
            'message':'Login successful',
            'role':user.role,
        },status=status.HTTP_200_OK)

        response.set_cookie(
            'access_token',
            str(refresh.access_token),
            httponly=True,
            secure=False,
            samesite='Lax',
            max_age=15*60)
        response.set_cookie(
            'refresh_token',
            str(refresh),
            httponly=True,
            secure=False,
            samesite='Lax',
            max_age=7*24*60*60
        )
        return response
    
class PendingUsersView(ListAPIView):
    permission_classes=[IsAdmin]
    serializer_class=UserApprovalSerializer

    def get_queryset(self):
        return User.objects.filter(approval_status=ApprovalStatus.PENDING)
    
class ApproveUserView(APIView):
    permission_classes=[IsAdmin]

    def post(self,request):
        user_id=self.kwargs['pk']
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

    def post(self,request):
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
    