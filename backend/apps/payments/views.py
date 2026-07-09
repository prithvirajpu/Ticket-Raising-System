from rest_framework.views import APIView
from apps.payments.services import (get_wallet_service,get_wallet_transactions_service,create_stripe_connect_account_service)
from apps.payments.services.create_withdrawal_request import create_withdrawal_request 
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
        result=get_wallet_transactions_service(request.user)
        return return_response(result)
    
class CreateConnectAccountView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        result=create_stripe_connect_account_service(request.user)
        return return_response(result)
    
class WithdrawalRequestView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        amount = request.data.get("amount")
        result = create_withdrawal_request(request.user,amount)

        return return_response(result)