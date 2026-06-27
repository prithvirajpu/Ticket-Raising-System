from apps.clients.models import ClientSubscription
from rest_framework import status
from django.core.cache import cache

import logging
logger = logging.getLogger(__name__)

def current_subscription_service(request):
    cache_key = f"curr_sub_plan_{request.user.id}"
    cached_data = cache.get(cache_key)

    if cached_data:
        return cached_data
    client = request.user.client_profile

    subscription = (
        ClientSubscription.objects
        .filter(
            client=client,
            status__in=['CANCEL_SCHEDULED','ACTIVE']
        ).select_related('plan').first()
    )
    logger.info('subsctiprion plan %s',subscription)
    if not subscription:
        return {
            "data": None,
            "errors": {
                "details": "No active subscription"
            },
            "status": status.HTTP_404_NOT_FOUND
        }

    result= {
        "data": {
            "id": subscription.id,
            "plan_name": subscription.plan.name,
            "status": subscription.status,
            "start_date": subscription.start_date,
            "end_date": subscription.end_date,
            'cancel_at_period_end':subscription.cancel_at_period_end,
            "cancel_scheduled_date":subscription.current_period_end.date() if subscription.current_period_end else None,
        },
        "errors": {},
        "status": status.HTTP_200_OK
    }
    cache.set(cache_key, result, timeout=60)
    return result