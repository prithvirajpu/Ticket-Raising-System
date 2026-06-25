from apps.payments.models import WithdrawalRequest
from apps.payments.serializer.withdrawal_serializer import withdrawal_serializer
from rest_framework import status

def getwithdrawal_list(user):
    data=WithdrawalRequest.objects.select_related(
        'user'
    ).filter(status='PENDING').order_by('-requested_at')
    serializer= withdrawal_serializer(data,many=True)
    return {
        'data':{'message':serializer.data},
        'errors':{},
        'status':status.HTTP_200_OK
    }
