from apps.payments.models import WithdrawalRequest,WalletTransaction
from apps.payments.serializer.withdrawal_serializer import withdrawal_serializer
from apps.admins.serializers.AdminWalletTransactionSerializer import AdminWalletTransactionSerializer
from rest_framework import status
from rest_framework.pagination import PageNumberPagination

def getwithdrawal_list(request):
    data=WithdrawalRequest.objects.select_related(
        'user'
    ).filter(status='PENDING').order_by('-requested_at')

    paginator= PageNumberPagination()
    paginator.page_size=10
    page=paginator.paginate_queryset(data,request)

    next_link=(paginator.get_next_link()
               if hasattr(paginator,'page')
               else None)
    previous_link =(paginator.get_previous_link()
                    if hasattr(paginator,'page')
                    else None)
    
    serializer= withdrawal_serializer(page,many=True)
    return {
        "paginator": {
            "count": data.count(),
            "next": next_link,
            "previous": previous_link,
            "page_size": paginator.page_size,
        },
        'data':{'message':serializer.data},
        'errors':{},
        'status':status.HTTP_200_OK
    }

def admin_wallet_transaction_service(request):
    queryset= (WalletTransaction.objects.select_related('wallet__user').order_by('-created_at'))

    paginator=PageNumberPagination()
    paginator.page_size=10
    page=paginator.paginate_queryset(queryset,request)

    serializer= AdminWalletTransactionSerializer(page,many=True)
    next_link=(paginator.get_next_link()
               if hasattr(paginator,'page')
               else None)
    previous_link =(paginator.get_previous_link()
                    if hasattr(paginator,'page')
                    else None)
    return {
        "paginator": {
            "count": queryset.count(),
            "next": next_link,
            "previous": previous_link,
            "page_size": paginator.page_size,
        },
        'data':{'message':serializer.data},
        'errors':{},
        'status':status.HTTP_200_OK
    }