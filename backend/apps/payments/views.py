from rest_framework.views import APIView
from apps.payments.services import (get_wallet_service,get_wallet_transactions_service)
from apps.payments.serializer import WalletSerializer
from rest_framework import status
from rest_framework.permissions import IsAuthenticated
from apps.core_app.utils import return_response
import logging 
logger= logging.getLogger(__name__)


class WalletAPIView(APIView):
    permission_classes=[IsAuthenticated]

    def get(self,request):
        result= get_wallet_service(request.user)
        return return_response(result)
    
class WalletTransactionAPIView(APIView):
    permission_classes =[IsAuthenticated]

    def get(self,request):
        result=get