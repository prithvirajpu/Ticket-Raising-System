from django.utils import timezone
from datetime import timedelta
from rest_framework import status
from apps.tickets.models import ClientSubscription,ClientProfile,SubscriptionPlan
from django.contrib.auth import get_user_model

import logging
logger = logging.getLogger(__name__)
User =get_user_model()

def process_checkout_completed(event):
    try:
        session= event['data']['object']
        metadata = session["metadata"]
        logger.info(f"Checkout session: {session}")
        logger.info(f"Metadata: {metadata}")
        plan_id = metadata["plan_id"]
        user_id = metadata["user_id"]
        stripe_subscription_id = session["subscription"]
        stripe_customer_id = session["customer"]

        user= User.objects.filter(id=user_id).first()

        if not user:
            return {
                'data':None,
                'errors':{"details":"User not found"},
                'status':status.HTTP_404_NOT_FOUND
            }
        client_profile= ClientProfile.objects.filter(user=user).first()
        if not client_profile:
            return {
                'data':None,
                'errors':{"details":"Client profile not found"},
                'status':status.HTTP_404_NOT_FOUND
            }
        plan = SubscriptionPlan.objects.filter(id=plan_id).first()
        if not plan:
            return {
                'data':None,
                'errors':{"details":"Plan not found"},
                'status':status.HTTP_404_NOT_FOUND
            }
        client_profile.stripe_customer_id = stripe_customer_id
        client_profile.save()

        ClientSubscription.objects.filter(client=client_profile,status='ACTIVE').update(status='EXPIRED')
        start_date = timezone.now().date()
        end_date = (start_date +timedelta(days=plan.duration_days))
        existing = ClientSubscription.objects.filter(
            stripe_subscription_id=
                stripe_subscription_id
        ).exists()

        if existing:
            return {
                "data": {"message":"Already processed"},
                "errors": {},
                "status": status.HTTP_200_OK
            }
        ClientSubscription.objects.create(client=client_profile,plan=plan,
                                        stripe_subscription_id=stripe_subscription_id,
                                        start_date=start_date,end_date=end_date,status='ACTIVE')
        return {
            "data": {"message":"Subscription activated"},
            "errors": {},
            "status": status.HTTP_200_OK
        }
    except Exception as e:
        logger.exception("Webhook processing failed")
        return {
            "data": None,
            "errors": {"details": str(e)},
            "status": 500
        }
    
def process_subscription_canceled(event):
    try:
        subscription = event['data']['object']
        stripe_subscription_id = subscription['id']

        sub = ClientSubscription.objects.filter(
            stripe_subscription_id=stripe_subscription_id,
            status='ACTIVE'
        ).first()

        if not sub:
            logger.warning("Subscription not found for cancel event")
            return

        sub.status = "CANCELLED"
        sub.save()

        logger.info(f"Subscription cancelled: {stripe_subscription_id}")

    except Exception as e:
        logger.exception(f"Cancel webhook failed: {str(e)}")

def process_subscription_updated(event):
    try:
        subscription = event['data']['object']
        stripe_subscription_id = subscription['id']
        logger.info(f"EVENT SUB ID: {stripe_subscription_id}")
        count = ClientSubscription.objects.filter(
    stripe_subscription_id=stripe_subscription_id
).count()

        logger.info(f"DB MATCH COUNT: {count}")
        cancel_at_period_end = getattr(subscription, "cancel_at_period_end", False)

        sub = ClientSubscription.objects.filter(
            stripe_subscription_id=stripe_subscription_id
        ).first()

        if not sub:
            return

        if cancel_at_period_end:
            sub.status = "CANCEL_SCHEDULED"
        else:
            # user reactivated subscription
            sub.status = "ACTIVE"

        sub.save()

        logger.info(f"Subscription updated: {stripe_subscription_id}")

    except Exception as e:
        logger.exception(f"Subscription update failed: {str(e)}")