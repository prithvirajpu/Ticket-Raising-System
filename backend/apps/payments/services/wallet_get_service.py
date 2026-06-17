from apps.payments.models import Wallet
from apps.payments.serializer import (WalletSerializer,WalletTransactionSerializer)
from rest_framework import status

def get_wallet_service(user):
    wallet= Wallet.objects.filter(user=user).first()
    if not wallet:
            return {
                'data':None,
                'errors':{'details':'Wallet not found'},
                'status': status.HTTP_404_NOT_FOUND
            }
    serializer=WalletSerializer(wallet)
    return {
          'data':{'message':serializer.data},
          'errors':{},
          'status':status.HTTP_200_OK
        }

def get_wallet_transactions_service(user):
    wallet= Wallet.objects.filter(user=user).first()
    if not wallet:
        return {
            'data':None,
            'errors':{'details':'Wallet not found'},
            'status': status.HTTP_404_NOT_FOUND
        }
    order_result=wallet.transactions.order_by('created_at')
    if order_result is None:
        return {
            'data':None,
            'errors':{'details':'Wallet transactions not found'},
            'status': status.HTTP_404_NOT_FOUND
        }
    serializer= WalletTransactionSerializer(order_result,many=True)
    return {
        'data':{'message':serializer.data},
        'errors':{},
        'status':status.HTTP_200_OK
        }
            