import stripe
from django.conf import settings
from rest_framework import status
from apps.clients.services.checkoutprocess import (process_subscription_renewal,process_subscription_updated,
                                                   process_checkout_completed,process_subscription_canceled,
                                                   process_payment_failed,process_subscription_created)
import logging
logger = logging.getLogger(__name__)


stripe.api_key=settings.STRIPE_SECRET_KEY

def handle_stripe_webhook_service(request):
    payload= request.body
    sig_header= request.META.get('HTTP_STRIPE_SIGNATURE')
    try:
        event= stripe.Webhook.construct_event(payload,sig_header,settings.STRIPE_WEBHOOK_SECRET)
    except Exception as e:
        return {
            'data':None,
            'errors':{"details":str(e)},
            'status':status.HTTP_400_BAD_REQUEST
        }
    
    if event['type'] =='checkout.session.completed':
        process_checkout_completed(event)
    if event['type'] =='customer.subscription.created':
        process_subscription_created(event)
    elif event['type'] == 'invoice.payment_succeeded':
        process_subscription_renewal(event)
    elif event['type'] == 'invoice.payment_failed':
        process_payment_failed(event)
    elif event['type'] == 'customer.subscription.updated':
        process_subscription_updated(event)
    elif event['type'] == 'customer.subscription.deleted':
        process_subscription_canceled(event)

    return {
        "data": {"message": "ignored"},
        "errors": {},
        "status": status.HTTP_200_OK
    }