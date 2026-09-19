from decimal import Decimal
from rest_framework import status
from apps.payments.models import Wallet, WithdrawalRequest
from apps.tickets.utils import send_notification
from django.contrib.auth import get_user_model
from django.db import transaction
from django.db.models import Sum
User=get_user_model()

def create_withdrawal_request(user, amount):

    amount = Decimal(str(amount))

    if amount <= 0:
        return {
            "data": None,
            "errors": {
                "details": "Invalid amount"
            },
            "status": status.HTTP_400_BAD_REQUEST
        }

    if not user.stripe_connect_account_id:
        return {
            "data": None,
            "errors": {
                "details": (
                    "Please connect your Stripe account "
                    "before requesting a withdrawal."
                )
            },
            "status": status.HTTP_400_BAD_REQUEST,
        }

    try:
        with transaction.atomic():

            # Lock wallet so two withdrawal requests
            # cannot calculate the available balance at the same time.
            wallet = (
                Wallet.objects
                .select_for_update()
                .filter(user=user)
                .first()
            )

            if not wallet:
                return {
                    "data": None,
                    "errors": {
                        "details": "Wallet not found"
                    },
                    "status": status.HTTP_400_BAD_REQUEST
                }

            # Calculate amount already reserved
            # by pending withdrawal requests.
            pending_amount = (
                WithdrawalRequest.objects
                .filter(
                    user=user,
                    status="PENDING"
                )
                .aggregate(
                    total=Sum("amount")
                )["total"]
                or Decimal("0")
            )

            # Actual amount currently available
            available_balance = wallet.balance - pending_amount

            if amount > available_balance:
                return {
                    "data": None,
                    "errors": {
                        "details": (
                            f"Insufficient available balance. "
                            f"Available balance: {available_balance}"
                        )
                    },
                    "status": status.HTTP_400_BAD_REQUEST
                }

            # Create withdrawal request
            withdrawal = WithdrawalRequest.objects.create(
                user=user,
                amount=amount,
                status="PENDING",
            )

            admin = (
                User.objects
                .filter(
                    role="ADMIN",
                    is_superuser=True
                )
                .first()
            )

            if admin:
                send_notification(
                    user_id=admin.id,
                    notification_type="WITHDRAWAL_REQUEST",
                    title="Withdrawal Request",
                    message=(
                        f"{user.name} requested a withdrawal "
                        f"of ${amount}."
                    ),
                    data={
                        "withdrawal_id": withdrawal.id,
                        "amount": str(amount),
                        "user_id": user.id,
                        "redirect_to": "/admin/wallet-transactions"
                    }
                )

            return {
                "data": {
                    "message": "Withdrawal request submitted"
                },
                "errors": {},
                "status": status.HTTP_201_CREATED
            }

    except Exception as e:
        return {
            "data": None,
            "errors": {
                "details": str(e)
            },
            "status": status.HTTP_400_BAD_REQUEST
        }