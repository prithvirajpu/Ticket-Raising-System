import csv

from django.http import HttpResponse

from ..dashboard.dashboard_ticket_service import get_ticket_dashboard
from ..dashboard.dashboard_wallet_service import get_wallet_dashboard
from ..dashboard.dashboard_user_service import get_user_dashboard
from ..dashboard.dashboard_report_service import get_ticket_report_dashboard


def export_dashboard_csv(period="7d"):

    tickets = get_ticket_dashboard(period)
    wallet = get_wallet_dashboard(period)
    users = get_user_dashboard()
    reports = get_ticket_report_dashboard(period)

    response = HttpResponse(content_type="text/csv")
    response["Content-Disposition"] = (
        'attachment; filename="dashboard_report.csv"'
    )

    writer = csv.writer(response)

    # ======================================
    # Ticket Summary
    # ======================================

    writer.writerow(["TICKET SUMMARY"])

    writer.writerow([
        "Total Tickets",
        "Open",
        "In Progress",
        "Resolved",
        "Closed",
    ])

    writer.writerow([
        tickets["total"],
        tickets["open"],
        tickets["pending"],
        tickets["resolved"],
        tickets["closed"],
    ])

    writer.writerow([])
    writer.writerow([])

    # ======================================
    # Wallet Summary
    # ======================================

    writer.writerow(["WALLET SUMMARY"])

    writer.writerow([
        "Total Wallet Balance",
        "Pending Withdrawals",
        "Approved Withdrawals",
    ])

    writer.writerow([
        wallet["wallet_balance"],
        wallet["pending_withdrawals"],
        wallet["approved_withdrawals"],
    ])

    writer.writerow([])
    writer.writerow([])

    # ======================================
    # User Summary
    # ======================================

    writer.writerow(["USER SUMMARY"])

    writer.writerow([
        "Total Users",
        "Customers",
        "Clients",
        "Managers",
        "Team Leads",
        "Agents",
    ])

    writer.writerow([
        users["total"],
        users["customers"],
        users["clients"],
        users["managers"],
        users["team_leads"],
        users["agents"],
    ])

    writer.writerow([])
    writer.writerow([])

    # ======================================
    # Ticket Status Chart
    # ======================================

    writer.writerow(["TICKET STATUS"])

    writer.writerow([
        "Status",
        "Count",
    ])

    status_labels = reports["ticket_status"]["labels"]
    status_data = reports["ticket_status"]["datasets"][0]["data"]

    for label, count in zip(status_labels, status_data):
        writer.writerow([label, count])

    writer.writerow([])
    writer.writerow([])

    # ======================================
    # Ticket Trend
    # ======================================

    writer.writerow(["TICKET TREND"])

    writer.writerow([
        "Period",
        "Tickets",
    ])

    trend_labels = reports["ticket_trend"]["labels"]
    trend_data = reports["ticket_trend"]["datasets"][0]["data"]

    for label, count in zip(trend_labels, trend_data):
        writer.writerow([label, count])

    return response