import stripe
from django.conf import settings
from apps.clients.models import SubscriptionPlan,ClientSubscription,ClientProfile

from rest_framework import status
import traceback
import logging
logger = logging.getLogger(__name__)

stripe.api_key=settings.STRIPE_SECRET_KEY

def stripe_checkout_service(request):
    try:
        plan_id=request.data.get('plan_id')
        customer_email=request.user.email
        if not plan_id:
            return {
                'data':None,
                'errors':{'details':'Plan id is required'},
                'status':status.HTTP_400_BAD_REQUEST
            }
        plan=SubscriptionPlan.objects.filter(id=plan_id).first()
        if not plan:
            return {
                'data':None,
                "errors": {"details": "Plan not found"
                },
                "status": status.HTTP_404_NOT_FOUND
            }
        client_profile = ClientProfile.objects.filter(
                user=request.user
            ).first()
        if not client_profile:
            return {
                "data": None,
                "errors": {
                    "details": "Client profile not found"
                },
                "status": status.HTTP_404_NOT_FOUND
            }
        existing_subscription = ClientSubscription.objects.filter(
                client=client_profile,
                status__in=["ACTIVE", "CANCEL_SCHEDULED"]
            ).exists()
        if existing_subscription:
            return {
                "data": None,
                "errors": {
                    "details": "You already have an active subscription"
                },
                "status": status.HTTP_400_BAD_REQUEST
            }

        if not plan.stripe_price_id:
            return {
                'data':None,
                "errors": {"details": "Stripe price id missing"
                },
                "status": status.HTTP_400_BAD_REQUEST
            }
        logger.info('plan_id %s and plan %s',plan_id,plan)
        session=stripe.checkout.Session.create(
            mode='subscription',
            customer_email=customer_email,
            payment_method_types=['card'],
            client_reference_id=str(request.user.id),
            line_items=[{
                'price':plan.stripe_price_id,
                'quantity':1,
                }],
            success_url='http://localhost:5173/subscription-success',
            cancel_url="http://localhost:5173/subscription-cancel",
            metadata={
                'plan_id':str(plan.id),
                'user_id':str(request.user.id),},
            subscription_data={
                "metadata": {
                    'plan_id': str(plan.id),
                    'user_id': str(request.user.id),
                }
            }
            )
        return {
            'data':{'checkout_url':session.url},
            'errors':{},
            'status':status.HTTP_200_OK,
        }
    except Exception as e:
        traceback.print_exc()
        return {
            'data':None,
            "errors": {"details": str(e)
            },
            "status": status.HTTP_500_INTERNAL_SERVER_ERROR
        }