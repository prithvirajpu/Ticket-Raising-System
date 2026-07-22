from decimal import Decimal
from rest_framework import status
from django.core.cache import cache
from apps.payments.models import Wallet,WalletTransaction

def debit_wallet(
    user,
    amount,
    transaction_type="WITHDRAWAL",
    description="",
    created_by=None
):
    wallet = Wallet.objects.filter(
        user=user
    ).first()

    if not wallet:
        return {
            'data':None,
            'errors':{'details':'Wallet not found'},
            'status': status.HTTP_404_NOT_FOUND
        }

    amount = Decimal(str(amount))

    if wallet.balance < amount:
        return {
            'data':None,
            'errors':{'details':'Insufficient wallet balance'},
            'status': status.HTTP_404_NOT_FOUND
        }

    wallet.balance -= amount
    wallet.save()

    transaction = WalletTransaction.objects.create(
        wallet=wallet,
        transaction_type=transaction_type,
        amount=-amount,
        description=description,
        created_by=created_by
    )
    cache.delete(f"wallet_balance_{user.id}")
    cache.delete(f"wallet_transactions_{user.id}")

    return transaction