from apps.payments.models import Wallet
from apps.payments.serializer import (WalletSerializer,WalletTransactionSerializer)
from rest_framework import status
from django.core.cache import cache


def get_wallet_service(user):
    cache_key = f"wallet_balance_{user.id}"
    cached_data = cache.get(cache_key)

    if cached_data:
        return cached_data
    wallet= Wallet.objects.filter(user=user).first()
    if not wallet:
            return {
                'data':None,
                'errors':{'details':'Wallet not found'},
                'status': status.HTTP_404_NOT_FOUND
            }
    serializer=WalletSerializer(wallet)
    result= {
          'data':{'message':serializer.data},
          'errors':{},
          'status':status.HTTP_200_OK
        }
    cache.set(cache_key, result, timeout=60)

    return result

def get_wallet_transactions_service(user):
    cache_key = f"wallet_transactions_{user.id}"
    cached_data = cache.get(cache_key)

    if cached_data:
        return cached_data

    wallet= Wallet.objects.filter(user=user).first()
    if not wallet:
        return {
            'data':None,
            'errors':{'details':'Wallet not found'},
            'status': status.HTTP_404_NOT_FOUND
        }
    order_result=wallet.transactions.order_by('-created_at')
    if order_result is None:
        return {
            'data':None,
            'errors':{'details':'Wallet transactions not found'},
            'status': status.HTTP_404_NOT_FOUND
        }
    serializer= WalletTransactionSerializer(order_result,many=True)
    result= {
        'data':{'message':serializer.data},
        'errors':{},
        'status':status.HTTP_200_OK
        }
    cache.set(cache_key, result, timeout=60)

    return result
            