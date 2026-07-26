
import csv
from django.utils import timezone

from django.http import HttpResponse

from apps.clients.models import ClientSubscription
from apps.payments.models import WalletTransaction

from ..finance.finance_summary_service import get_finance_summary


def export_finance_csv():
    summary = get_finance_summary()

    response = HttpResponse(content_type="text/csv")
    response["Content-Disposition"] = (
        'attachment; filename="finance_report.csv"'
    )

    writer = csv.writer(response)

    # ==========================
    # Finance Summary
    # ==========================

    writer.writerow(["FINANCE SUMMARY"])

    writer.writerow([
        "Report Date",
        "Revenue",
        "Salary Paid",
        "Pending Withdrawals",
        "Net Profit",
    ])

    writer.writerow([
        timezone.now().date(),
        summary["revenue"],
        summary["salary_paid"],
        summary["pending_salary"],
        summary["net_profit"],
    ])

    writer.writerow([])
    writer.writerow([])

    # ==========================
    # Subscription Revenue
    # ==========================

    writer.writerow(["CLIENT SUBSCRIPTIONS"])

    writer.writerow([
        "Company",
        "Plan",
        "Amount",
        "Status",
        "Created On",
        "Expires On",
    ])

    subscriptions = (
        ClientSubscription.objects
        .select_related(
            "client",
            "client__user",
            "plan",
        )
        .order_by("-created_at")
    )

    for subscription in subscriptions:
        writer.writerow([
            subscription.client.company_name,
            subscription.plan.name,
            subscription.plan.price,
            subscription.status,
            subscription.created_at.date(),
            subscription.end_date,
        ])

    writer.writerow([])
    writer.writerow([])

    # ==========================
    # Salary Distribution
    # ==========================

    writer.writerow(["SALARY DISTRIBUTION"])

    writer.writerow([
        "Date",
        "Employee",
        "Role",
        "Salary",
    ])

    salaries = (
        WalletTransaction.objects
        .select_related("wallet__user")
        .filter(transaction_type="SALARY")
        .order_by("-created_at")
    )

    for salary in salaries:

        writer.writerow([
            salary.created_at.date(),
            salary.wallet.user.name,
            salary.wallet.user.role,
            salary.amount,
        ])

    return response