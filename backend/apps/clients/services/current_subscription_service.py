from apps.tickets.models import ClientSubscription
from rest_framework import status

import logging
logger = logging.getLogger(__name__)

def current_subscription_service(request):
    client = request.user.client_profile

    subscription = (
        ClientSubscription.objects
        .filter(
            client=client,
            status='ACTIVE'
        )
        .select_related('plan')
        .first()
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

    return {
        "data": {
            "id": subscription.id,
            "plan_name": subscription.plan.name,
            "status": subscription.status,
            "start_date": subscription.start_date,
            "end_date": subscription.end_date,
            'cancel_at_period_end':subscription.cancel_at_period_end,
        },
        "errors": {},
        "status": status.HTTP_200_OK
    }