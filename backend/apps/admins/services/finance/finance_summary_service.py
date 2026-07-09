from django.db.models import Sum

from apps.clients.models import ClientSubscription
from apps.payments.models import WalletTransaction,WithdrawalRequest


def get_finance_summary():

    revenue = (
        ClientSubscription.objects.aggregate(
            total=Sum("plan__price")
        )["total"] or 0
    )

    salary_paid = (
        WalletTransaction.objects.filter(
            transaction_type__in=[
                "SALARY",
                "INCENTIVE",
            ]
        ).aggregate(
            total=Sum("amount")
        )["total"] or 0
    )

    pending_salary_count = (
        WithdrawalRequest.objects.filter(
            status="PENDING"
        ).count()
    )

    return {
        "revenue": revenue,
        "salary_paid": salary_paid,
        "pending_salary": pending_salary_count,
        "net_profit": revenue - salary_paid,
    }