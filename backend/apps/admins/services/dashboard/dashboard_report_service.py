from datetime import timedelta
from django.db.models import Count
from django.db.models.functions import TruncDate, TruncMonth
from django.utils import timezone

from apps.tickets.models import Ticket


def get_ticket_report_dashboard(period):
    today = timezone.localdate()

    tickets = Ticket.objects.filter(is_ai_generated=False,
                                 is_training_ticket=False)

    if period == "7d":
        start_date = today - timedelta(days=6)
        tickets = tickets.filter(created_at__date__gte=start_date)

    elif period == "30d":
        start_date = today - timedelta(days=29)
        tickets = tickets.filter(created_at__date__gte=start_date)

    elif period == "12m":
        start_date = today - timedelta(days=365)
        tickets = tickets.filter(created_at__date__gte=start_date)
    labels = []
    data = []

    if period in ["7d", "30d"]:

        queryset = (
            tickets.annotate(day=TruncDate("created_at"))
            .values("day")
            .annotate(count=Count("id"))
            .order_by("day")
        )

        counts = {
            item["day"]: item["count"]
            for item in queryset
        }

        total_days = 7 if period == "7d" else 30

        first_day = today - timedelta(days=total_days - 1)

        for i in range(total_days):
            day = first_day + timedelta(days=i)

            labels.append(day.strftime("%d %b"))
            data.append(counts.get(day, 0))

    elif period == "12m":

        queryset = (
            tickets.annotate(month=TruncMonth("created_at"))
            .values("month")
            .annotate(count=Count("id"))
            .order_by("month")
        )

        counts = {
            (item["month"].year, item["month"].month): item["count"]
            for item in queryset
        }

        current = today.replace(day=1)

        months = []

        for _ in range(12):
            months.append(current)

            if current.month == 1:
                current = current.replace(
                    year=current.year - 1,
                    month=12
                )
            else:
                current = current.replace(
                    month=current.month - 1
                )

        months.reverse()

        for month in months:

            labels.append(month.strftime("%b"))

            data.append(
                counts.get(
                    (month.year, month.month),
                    0
                )
            )

    return {
        "ticket_status": {
            "labels": [
                "Open",
                "In Progress",
                "Resolved",
                "Closed",
            ],
            "datasets": [
                {
                    "data": [
                        tickets.filter(status="OPEN").count(),
                        tickets.filter(status="IN_PROGRESS").count(),
                        tickets.filter(status="RESOLVED").count(),
                        tickets.filter(status="CLOSED").count(),
                    ]
                }
            ],
        },

        "ticket_trend": {
            "labels": labels,
            "datasets": [
                {
                    "label": "Tickets",
                    "data": data,
                }
            ],
        },
    }