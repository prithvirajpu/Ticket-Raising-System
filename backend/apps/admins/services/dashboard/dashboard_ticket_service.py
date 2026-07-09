from apps.tickets.models import Ticket
from django.utils import timezone
from datetime import timedelta

def get_ticket_dashboard(period):

    tickets = Ticket.objects.filter(is_ai_generated=False,
                                 is_training_ticket=False)

    if period == "7d":
        tickets = tickets.filter(
            created_at__date__gte=timezone.localdate() - timedelta(days=6)
        )

    elif period == "30d":
        tickets = tickets.filter(
            created_at__date__gte=timezone.localdate() - timedelta(days=29)
        )

    elif period == "12m":
        tickets = tickets.filter(
            created_at__date__gte=timezone.localdate() - timedelta(days=365)
        )

    return {
        "total": tickets.count(),
        "open": tickets.filter(status="OPEN").count(),
        "pending": tickets.filter(status="IN_PROGRESS").count(),
        "resolved": tickets.filter(status="RESOLVED").count(),
        "closed": tickets.filter(status="CLOSED").count(),
    }