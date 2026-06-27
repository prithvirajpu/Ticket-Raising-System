from decimal import Decimal
from rest_framework import status
from apps.payments.models import Wallet, WithdrawalRequest

def create_withdrawal_request(user, amount):

    wallet = Wallet.objects.filter(
        user=user
    ).first()

    if not wallet:
        return {
            "data": None,
            "errors": {"details": "Wallet not found"},
            "status": status.HTTP_400_BAD_REQUEST
        }
    if not user.stripe_connect_account_id:
        return {
            "data": None,
            "errors": {
                "details": "Please connect your Stripe account before requesting a withdrawal."
            },
            "status": status.HTTP_400_BAD_REQUEST,
        }

    amount = Decimal(str(amount))
    if amount <= 0:
        return {
            "data": None,
            "errors": {"details": "Invalid amount"},
            "status": status.HTTP_400_BAD_REQUEST
        }

    if wallet.balance < amount:
        raise Exception("Insufficient balance")
    WithdrawalRequest.objects.create(
        user=user,
        amount=amount,
    )

    return {
        "data": {
            "message": "Withdrawal request submitted"
        },
        "errors": {},
        "status": status.HTTP_201_CREATED
    }