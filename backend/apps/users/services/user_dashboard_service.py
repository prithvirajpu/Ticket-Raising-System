from apps.tickets.models import Ticket
from apps.clients.models import ClientProfile
from rest_framework import status
from django.contrib.auth import get_user_model
from django.core.cache import cache


User=get_user_model()

def user_dashboard(user, client_id):
    cache_key = f"user_dashboard_{user.id}_{client_id}"
    cached_data = cache.get(cache_key)

    if cached_data:
        return cached_data

    tickets = Ticket.objects.filter(
        created_by=user,
        client_profile_id=client_id
    )

    result = {
        "data": {
            "message": {
                "total_tickets": tickets.count(),
                "resolved": tickets.filter(status="RESOLVED").count(),
                "escalated": tickets.filter(status="ESCALATED").count(),
                "in_progress": tickets.filter(status="IN_PROGRESS").count(),
            }
        },
        "errors": {},
        "status": status.HTTP_200_OK,
    }

    cache.set(cache_key, result, timeout=60)

    return result