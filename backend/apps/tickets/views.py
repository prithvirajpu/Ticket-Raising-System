from rest_framework.views import APIView
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from apps.core_app.utils import return_response
from apps.tickets.services import (notification_service,
                                   escalate_ticket_service,resolve_ticket_service,
                                   send_message_service,get_messages_service,
                                   mark_as_read_notification,mark_all_notifications_read_service,
                                   get_training_messages_service)

# tickets/views/dev_auth.py

from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import AllowAny

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
        result = get_messages_service(request.user, ticket_id,request=request)
        return Response(result)

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
    
class NotificationListView(APIView):
    permission_classes =[IsAuthenticated]

    def get(self,request):
        result= notification_service(request)
        return return_response(result)
    
class MarkNotificationReadView(APIView):
    permission_classes= [IsAuthenticated]

    def patch(self,request,notification_id):
        result= mark_as_read_notification(request,notification_id)
        return return_response(result)
    
class MarkAllNotificationsReadView(APIView):
    permission_classes = [IsAuthenticated]

    def put(self, request):
        result = mark_all_notifications_read_service(request)
        return return_response(result)
    
class TrainingMessagesAPIView(APIView):
    permission_classes= [IsAuthenticated]

    def get(self, request, ticket_id):
        result = get_training_messages_service(request,ticket_id)
        return return_response(result)
    
