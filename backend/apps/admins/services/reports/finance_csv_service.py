
import csv

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
        "Revenue",
        "Salary Paid",
        "Pending Withdrawals",
        "Net Profit",
    ])

    writer.writerow([
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
            subscription.end_date,
        ])

    writer.writerow([])
    writer.writerow([])

    # ==========================
    # Salary Distribution
    # ==========================

    writer.writerow(["SALARY DISTRIBUTION"])

    writer.writerow([
        "Employee",
        "Role",
        "Salary",
        "Date",
    ])

    salaries = (
        WalletTransaction.objects
        .select_related("wallet__user")
        .filter(transaction_type="SALARY")
        .order_by("-created_at")
    )

    for salary in salaries:

        writer.writerow([
            salary.wallet.user.name,
            salary.wallet.user.role,
            salary.amount,
            salary.created_at.date(),
        ])

    return response