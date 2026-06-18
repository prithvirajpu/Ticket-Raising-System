import stripe
from django.utils import timezone
from datetime import timedelta,datetime
from rest_framework import status
from apps.clients.models import ClientSubscription,ClientProfile,SubscriptionPlan
from django.contrib.auth import get_user_model

import logging
logger = logging.getLogger(__name__)
User =get_user_model()

def _get_metadata(obj):
    """Robust extraction of metadata from Stripe objects."""
    if not obj:
        return {}
    
    metadata_obj = getattr(obj, 'metadata', None)
    if metadata_obj is None:
        return {}
    
    if isinstance(metadata_obj, dict):
        return metadata_obj
    
    if hasattr(metadata_obj, '_values'):
        values = getattr(metadata_obj, '_values', {})
        if isinstance(values, dict):
            return values
    
    if hasattr(metadata_obj, '_data'):
        data = getattr(metadata_obj, '_data', {})
        if isinstance(data, dict):
            return data
    
    try:
        if hasattr(metadata_obj, 'keys'):
            return {k: metadata_obj[k] for k in metadata_obj.keys()}
    except:
        pass
    
    try:
        import stripe
        if hasattr(stripe.util, 'convert_to_dict'):
            converted = stripe.util.convert_to_dict(metadata_obj)
            if isinstance(converted, dict):
                return converted
    except:
        pass
    
    logger.warning(f"Could not extract metadata. Type: {type(metadata_obj)}")
    return {}


def _safe_getattr(obj, attr, default=None):
    """Robust attribute access for Stripe objects."""
    if not obj:
        return default
    
    try:
        # Direct attribute
        value = getattr(obj, attr, None)
        if value is not None:
            return value
    except:
        pass

    # Internal _data
    try:
        if hasattr(obj, '_data') and attr in obj._data:
            return obj._data[attr]
    except:
        pass

    # Stripe convert_to_dict
    try:
        from stripe import util
        data = util.convert_to_dict(obj)
        return data.get(attr, default)
    except:
        pass

    return default
    
    
def process_checkout_completed(event):
    try:
        session = event["data"]["object"]

        logger.info(f"[checkout.session.completed] session_id={session.id}")

        metadata = _get_metadata(session)
        logger.info(f"✅ Session metadata extracted: {metadata}")

        plan_id = metadata.get("plan_id")
        user_id = metadata.get("user_id")

        if not user_id or not plan_id:
            logger.error("Missing metadata in checkout.session.completed")
            return

        user = User.objects.filter(id=user_id).first()
        if not user:
            logger.error(f"User not found: {user_id}")
            return

        client_profile = ClientProfile.objects.filter(user=user).first()
        if not client_profile:
            logger.error(f"ClientProfile not found for user {user_id}")
            return

        client_profile.stripe_customer_id = getattr(session, "customer", None)
        client_profile.save(update_fields=["stripe_customer_id"])

        logger.info(
            f"[checkout.session.completed] saved stripe_customer_id={client_profile.stripe_customer_id}"
        )

    except Exception as e:
        logger.exception(f"checkout.session.completed failed: {str(e)}")


def process_subscription_created(event):
    try:
        subscription = event["data"]["object"]
        sub_id = _safe_getattr(subscription, "id")
        customer_id = _safe_getattr(subscription, "customer")

        logger.info(f"[subscription.created] id={sub_id}")

        metadata = _get_metadata(subscription)
        logger.info(f"✅ Subscription metadata: {metadata}")

        plan_id = metadata.get("plan_id")
        user_id = metadata.get("user_id")

        if not sub_id:
            logger.error("Missing subscription id")
            return

        if not user_id or not plan_id:
            logger.error(f"❌ Missing metadata. Got: {metadata}")
            return

        user = User.objects.filter(id=user_id).first()
        if not user:
            logger.error(f"User not found: {user_id}")
            return

        client_profile = ClientProfile.objects.filter(user=user).first()
        if not client_profile:
            logger.error(f"ClientProfile not found: {user_id}")
            return

        plan = SubscriptionPlan.objects.filter(id=plan_id).first()
        if not plan:
            logger.error(f"Plan not found: {plan_id}")
            return

        # Update customer ID
        if customer_id:
            client_profile.stripe_customer_id = customer_id
            client_profile.save(update_fields=["stripe_customer_id"])

        # === RETRIEVE SUBSCRIPTION ===
        stripe_sub = stripe.Subscription.retrieve(sub_id)
        
        # Strongest possible extraction of current_period_end
        current_period_end_ts = _safe_getattr(stripe_sub, 'current_period_end')
        
        if current_period_end_ts is None:
            # Extra fallback
            if hasattr(stripe_sub, '_data'):
                current_period_end_ts = stripe_sub._data.get('current_period_end')
        
        if current_period_end_ts is None:
            logger.error("❌ Could not get current_period_end. Please check Stripe response.")
            # Emergency fallback - use 30 days from now
            current_period_end = timezone.now() + timedelta(days=30)
        else:
            current_period_end = datetime.fromtimestamp(
                current_period_end_ts, tz=timezone.utc
            )

        # Create or update the record
        obj, created = ClientSubscription.objects.update_or_create(
            stripe_subscription_id=sub_id,
            defaults={
                "client": client_profile,
                "plan": plan,
                "start_date": timezone.now().date(),
                "end_date": current_period_end.date(),
                "current_period_end": current_period_end,
                "status": "ACTIVE",
            }
        )

        logger.info(f"[subscription.created] ✅ SUCCESS - Saved subscription id={sub_id} | Created: {created}")

    except Exception as e:
        logger.exception(f"subscription.created failed: {str(e)}")

def process_subscription_canceled(event):
    try:
        subscription = event['data']['object']
        stripe_subscription_id = getattr(subscription, "id", None)

        sub = ClientSubscription.objects.filter(
            stripe_subscription_id=stripe_subscription_id,
        ).first()

        if not sub:
            logger.warning("Subscription not found for cancel event")
            return

        sub.status = "CANCELLED"
        sub.cancel_at_period_end= True
        sub.save()

        logger.info(f"Subscription cancelled: {stripe_subscription_id}")

    except Exception as e:
        logger.exception(f"Cancel webhook failed: {str(e)}")

def process_subscription_updated(event):
    logger.info("SUBSCRIPTION UPDATED WEBHOOK RECEIVED")
    try:
        subscription = event['data']['object']
        stripe_subscription_id  = getattr(subscription, "id", None)
        cancel_at_period_end = getattr(subscription, "cancel_at_period_end", False)

        logger.info(
    f"subscription.updated received "
    f"id={subscription.id} "
    f"cancel_at_period_end={cancel_at_period_end}"
)
        sub = ClientSubscription.objects.filter(
            stripe_subscription_id=stripe_subscription_id
        ).first()

        if not sub:
            return
        sub.cancel_at_period_end=cancel_at_period_end

        if cancel_at_period_end:
            sub.status = "CANCEL_SCHEDULED"
        else:
            sub.status = "ACTIVE"

        sub.save()
        logger.info(
                f"Updating DB record "
                f"{stripe_subscription_id}"
            )
        sub.save()
        logger.info(f"Subscription updated: {stripe_subscription_id}")

    except Exception as e:
        logger.exception(f"Subscription update failed: {str(e)}")


def process_subscription_renewal(event):
    try:
        invoice = event['data']['object']

        stripe_subscription_id = getattr(invoice,'subscription',None)

        sub = ClientSubscription.objects.filter(
            stripe_subscription_id=stripe_subscription_id
        ).first()

        if not sub:
            logger.warning(
                f"Subscription not found: {stripe_subscription_id}"
            )
            return
        stripe_sub = stripe.Subscription.retrieve(
            stripe_subscription_id
        )
        current_period_end = datetime.fromtimestamp(
            stripe_sub.current_period_end,
            tz=timezone.utc
        )

        sub.current_period_end = current_period_end
        sub.end_date = current_period_end.date()
        sub.status = "ACTIVE"
        sub.cancel_at_period_end = False
        sub.save()

        logger.info(
            f"Subscription renewed: {stripe_subscription_id}"
        )

    except Exception as e:
        logger.exception(
            f"Renewal webhook failed: {str(e)}"
        )

def process_payment_failed(event):
    try:
        invoice = event['data']['object']

        stripe_subscription_id = getattr(invoice,'subscription',None)

        sub = ClientSubscription.objects.filter(
            stripe_subscription_id=stripe_subscription_id
        ).first()

        if not sub:
            return

        sub.status = "PAST_DUE"
        sub.save()

        logger.warning(
            f"Payment failed for {stripe_subscription_id}"
        )

    except Exception as e:
        logger.exception(
            f"Payment failed webhook error: {str(e)}"
        )