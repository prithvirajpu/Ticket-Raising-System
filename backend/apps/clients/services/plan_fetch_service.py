from apps.clients.models import SubscriptionPlan
from rest_framework import status
from django.core.cache import cache

def plan_fetch_service(request):
    cache_key = f"sub_plans_{request.user.id}"
    cached_data = cache.get(cache_key)

    if cached_data:
        return cached_data
    plans=SubscriptionPlan.objects.all().values(
            'id','name', 'price', 'duration_days', 'max_agents', 'max_tickets'
        ).order_by('price')
    result= {
        'data':{'message':list(plans)},
        'errors':{},
        'status':status.HTTP_200_OK
    }
    cache.set(cache_key, result, timeout=60)
    return result
