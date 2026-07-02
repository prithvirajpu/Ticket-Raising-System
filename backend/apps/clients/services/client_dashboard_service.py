from rest_framework import status

from apps.accounts.models import User
from apps.clients.models import ClientProfile, ClientSubscription
from apps.users.models import ClientUser
from apps.tickets.models import Ticket
from django.core.cache import cache


def get_client_dashboard(user):
    cache_key = f"client_dashboard_{user.id}"
    cached_data = cache.get(cache_key)

    if cached_data:
        return cached_data

    client= ClientProfile.objects.filter(user=user).first()
    if not client:
        return {
            "data": None,
            "errors": {"details": "Client not found"},
            "status": status.HTTP_400_BAD_REQUEST
        }
    subscription= ClientSubscription.objects.filter(client=client,status__in=['ACTIVE','CANCEL_SCHEDULED']).select_related(
        'plan').first()
    
    current_plan=(subscription.plan.name
    if subscription else 'No active plan')

    active_users=ClientUser.objects.filter(client_profile=client,user__is_active=True).count()

    open_tickets = Ticket.objects.filter(
        client=client,status="OPEN"
    ).count()

    total_tickets = Ticket.objects.filter(
        client=client
    ).count()
    result= {
        "data": {
            "message": {
                "current_plan": current_plan,
                "active_users": active_users,
                "open_tickets": open_tickets,
                "total_tickets": total_tickets,
            }
        },
        "errors": {},
        "status": status.HTTP_200_OK
    }
    cache.set(cache_key, result, timeout=60)

    return result