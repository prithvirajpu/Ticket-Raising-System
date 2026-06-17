from decimal import Decimal
from rest_framework import status
from apps.payments.models import (Wallet,WalletTransaction)

def credit_wallet(
        user,amount,transaction_type,description='',created_by=None
    ):
    wallet=Wallet.objects.filter(user=user).first()
    if not wallet:
        return {
            'data':None,
            'errors':{'details':'Wallet not found'},
            'status': status.HTTP_404_NOT_FOUND
        }
    amount=Decimal(str(amount))
    wallet.balance+=amount
    wallet.save()

    transaction=WalletTransaction.objects.create(
        wallet=wallet,transaction_type=transaction_type,
        amount=amount,description=description,created_by=created_by
    )
    return transaction