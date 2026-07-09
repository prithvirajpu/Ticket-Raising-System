from django.db.models import Sum
from apps.payments.models import Wallet, WithdrawalRequest
from django.utils import timezone
from datetime import timedelta

def get_wallet_dashboard(period):
    withdrawals = WithdrawalRequest.objects.all()

    if period == "7d":
        withdrawals = withdrawals.filter(
            requested_at__date__gte=timezone.localdate() - timedelta(days=6)
        )

    elif period == "30d":
        withdrawals = withdrawals.filter(
            requested_at__date__gte=timezone.localdate() - timedelta(days=29)
        )

    elif period == "12m":
        withdrawals = withdrawals.filter(
            requested_at__date__gte=timezone.localdate() - timedelta(days=365)
        )

    return {
        "wallet_balance": Wallet.objects.aggregate(
            total=Sum("balance")
        )["total"] or 0,

        "pending_withdrawals": withdrawals.filter(
            status="PENDING"
        ).count(),

        "approved_withdrawals": withdrawals.filter(
            status="APPROVED"
        ).count(),
    }