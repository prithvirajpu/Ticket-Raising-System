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
from .services import (update_client_profile_service,upload_client_doc_service)
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