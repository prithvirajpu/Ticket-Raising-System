from apps.payments.models import Wallet
from apps.payments.serializer import (WalletSerializer,WalletTransactionSerializer)
from rest_framework import status
from django.core.cache import cache
from rest_framework.pagination import PageNumberPagination


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

def get_wallet_transactions_service(request, user):

    page_number = request.query_params.get("page", 1)

    cache_key = f"wallet_transactions_{user.id}_page_{page_number}"

    cached_data = cache.get(cache_key)

    if cached_data:
        return cached_data

    wallet = Wallet.objects.filter(user=user).first()

    if not wallet:
        return {
            "data": None,
            "errors": {
                "details": "Wallet not found"
            },
            "status": status.HTTP_404_NOT_FOUND
        }

    queryset = wallet.transactions.order_by("-created_at")

    paginator = PageNumberPagination()
    paginator.page_size = 10

    page = paginator.paginate_queryset(
        queryset,
        request
    )

    serializer = WalletTransactionSerializer(
        page,
        many=True
    )

    result = {
        "paginator": {
            "count": queryset.count(),
            "next": paginator.get_next_link(),
            "previous": paginator.get_previous_link(),
            "page_size": paginator.page_size,
        },
        "data": {
            "message": serializer.data
        },
        "errors": {},
        "status": status.HTTP_200_OK
    }

    cache.set(
        cache_key,
        result,
        timeout=60
    )

    return result