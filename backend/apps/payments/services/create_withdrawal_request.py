from decimal import Decimal
from rest_framework import status
from apps.payments.models import Wallet, WithdrawalRequest
from apps.tickets.utils import send_notification
from django.contrib.auth import get_user_model
User=get_user_model()

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
        return {
        "data": None,
        "errors": {"details": "Insufficient wallet balance"},
        "status": status.HTTP_400_BAD_REQUEST,
    }
    withdrawal=WithdrawalRequest.objects.create(
        user=user,
        amount=amount,
    )
    admin=User.objects.filter(role='ADMIN',is_superuser=True).first()
    send_notification(
        user_id=admin.id,
        notification_type='WITHDRAWAL_REQUEST',
        title='Withdrawal Request',
        message=f'{user.name} requested a withdrawal of ${amount}.',
        data={
            "withdrawal_id": withdrawal.id,
            "amount": str(amount),
            "user_id": user.id,
            "redirect_to": "/admin/wallet-system"
        }
    )

    return {
        "data": {
            "message": "Withdrawal request submitted"
        },
        "errors": {},
        "status": status.HTTP_201_CREATED
    }