from apps.tickets.models import Ticket
from rest_framework import status
from django.contrib.auth import get_user_model
from django.core.cache import cache


User=get_user_model()

def user_dashboard(user):
    cache_key = f"user_dashboard_{user.id}"
    cached_data = cache.get(cache_key)

    if cached_data:
        return cached_data
    total_tickets= Ticket.objects.filter(created_by_id=user.id).count()
    escalated=Ticket.objects.filter(created_by_id=user.id,status='ESCALATED').count()
    in_progress=Ticket.objects.filter(created_by_id=user.id,status='IN_PROGRESS').count()
    resolved=Ticket.objects.filter(created_by_id=user.id,status='RESOLVED').count()
    result= {
        'data':{'message':{
            'resolved':resolved,
            'total_tickets':total_tickets,
            'escalated':escalated,
            'in_progress':in_progress
        }},
        'errors':{},
        'status':status.HTTP_200_OK
    }
    cache.set(cache_key, result, timeout=60)

    return result