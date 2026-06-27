from apps.tickets.models import Ticket
from apps.core_app.constants import UserRole
from rest_framework import status
from django.contrib.auth import get_user_model
from django.core.cache import cache


User=get_user_model()

def agent_dashboard(user):
    cache_key = f"agent_dashboard_{user.id}"
    cached_data = cache.get(cache_key)

    if cached_data:
        return cached_data
    assigned_tickets= Ticket.objects.filter(assigned_to_id=user.id).count()
    open=Ticket.objects.filter(assigned_to_id=user.id,status='OPEN').count()
    in_progress=Ticket.objects.filter(assigned_to_id=user.id,status='IN_PROGRESS').count()
    result= {
        'data':{'message':{
            'assigned_tickets':assigned_tickets,
            'open':open,
            'in_progress':in_progress
        }},
        'errors':{},
        'status':status.HTTP_200_OK
    }
    cache.set(cache_key, result, timeout=60)

    return result
