import stripe
from django.conf import settings
from rest_framework import status
from apps.tickets.models import ClientSubscription

import logging
logger = logging.getLogger(__name__)


stripe.api_key=settings.STRIPE_SECRET_KEY

def cancel_subscription_service(request):
    try:
        client= request.user.client_profile
        subscription=(
            ClientSubscription.objects.filter(
                client=client,status='ACTIVE'
            ).first()
        )
        if not subscription:
            return {
                "data": None,
                "errors": {"details": "No active subscription"},
                "status": status.HTTP_404_NOT_FOUND
            }
        stripe.Subscription.modify(
            subscription.stripe_subscription_id,
            cancel_at_period_end=True
        )
        subscription.cancel_at_period_end=True
        subscription.save(update_fields=['cancel_at_period_end'])
        return {
            "data": {"message": "Subscription will be cancelled at period end"},
            "errors": {},
            "status": status.HTTP_200_OK
        }
    except Exception as e:
        return {
            "data": None,
            "errors": {"details": str(e)},
            "status": status.HTTP_500_INTERNAL_SERVER_ERROR
        }