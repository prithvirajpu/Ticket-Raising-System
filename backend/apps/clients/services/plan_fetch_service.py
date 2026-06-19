from apps.clients.models import SubscriptionPlan
from rest_framework import status

def plan_fetch_service(request):
    plans=SubscriptionPlan.objects.all().values(
            'id','name', 'price', 'duration_days', 'max_agents', 'max_tickets'
        ).order_by('price')
    return {
        'data':{'message':list(plans)},
        'errors':{},
        'status':status.HTTP_200_OK
    }
