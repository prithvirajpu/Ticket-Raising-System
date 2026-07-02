from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.pagination import PageNumberPagination
from rest_framework.generics import ListAPIView 
from rest_framework.permissions import IsAuthenticated
from apps.core_app.permissions import IsAdmin
from apps.core_app.constants import ApprovalStatus
from apps.core_app.utils import return_response
from apps.core_app.models import AgentApplication
from rest_framework.parsers import MultiPartParser, FormParser
from .services import (plan_fetch_service,get_client_integration_keys,
                       update_client_profile_service,upload_client_doc_service,
                       current_subscription_service,stripe_checkout_service,
                       handle_stripe_webhook_service,cancel_subscription_service,
                       regenerate_client_keys_service,get_client_dashboard,
                       update_app_url_service)
from ..tickets.serializer import TicketSerializer
from django.contrib.auth import get_user_model

import logging
logger=logging.getLogger(__name__)

User=get_user_model()

class UpdateClientProfileView(APIView):
    permission_classes=[IsAuthenticated]

    def put(self,request):
        result=update_client_profile_service(request.user,request.data)
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
    
class SubscriptionPlanView(APIView):
    permission_classes=[IsAuthenticated]

    def get(self,request):
        result=plan_fetch_service(request)
        return return_response(result)
    
class CurrentSubscriptionAPIView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        result = current_subscription_service(request)
        return return_response(result)
    
class CreateCheckoutSessionAPIView(APIView):
    permission_classes =[IsAuthenticated]

    def post(self,request):
        result= stripe_checkout_service(request)
        return return_response(result)

class StripeWebhookAPIView(APIView):
    authentication_classes = []
    permission_classes = []

    def post(self, request):
        result = handle_stripe_webhook_service(request)
        return return_response(result)
    
class CancelSubscriptionAPIView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        result = cancel_subscription_service(request)
        return return_response(result)
    
class ClientIntegrationKeysAPIView(APIView):
    permission_classes= [IsAuthenticated]

    def get(self,request):
        result= get_client_integration_keys(request.user)
        return return_response(result)
    
class RegenerateClientKeysAPIView(APIView):
    permission_classes = [IsAuthenticated]

    def patch(self, request):
        result = regenerate_client_keys_service(request.user)
        return return_response(result)
    
class ClientDashboardAPIView(APIView):
    permission_classes=[IsAuthenticated]

    def get(self,request):
        logger.info('client dashboard hit')
        result=get_client_dashboard(request.user)
        return return_response(result)
    
class UpdateAppUrlView(APIView):
    permission_classes=[IsAuthenticated]

    def patch(self,request):
        result= update_app_url_service(request.user,request.data)
        return return_response(result)