import stripe
import traceback
import logging
from decimal import Decimal
from django.conf import settings
from rest_framework import status

from apps.clients.models import SubscriptionPlan

logger = logging.getLogger(__name__)

stripe.api_key = settings.STRIPE_SECRET_KEY


def update_subscription_plan_service(plan_id, data):
    try:
        plan = SubscriptionPlan.objects.filter(id=plan_id).first()

        if not plan:
            return {
                "data": None,
                "errors": {
                    "details": "Subscription plan not found"
                },
                "status": status.HTTP_400_BAD_REQUEST
            }

        name = data.get("name")
        price = data.get("price")
        duration_days = data.get("duration_days")
        max_agents = data.get("max_agents")
        max_tickets = data.get("max_tickets")
        is_active = data.get("is_active")
        if price is not None:

            new_price = Decimal(str(price))

            if new_price <= 0:
                return {
                    "data": None,
                    "errors": {
                        "details": "Price must be greater than 0"
                    },
                    "status": status.HTTP_400_BAD_REQUEST
                }

            if new_price != plan.price:

                stripe_price = stripe.Price.create(
                    product=plan.stripe_product_id,
                    unit_amount=int(new_price * 100),
                    currency="usd",
                    recurring={
                        "interval": "month"
                    }
                )
                logger.info(
    "Created new Stripe price: %s for plan: %s",
    stripe_price.id,
    plan.id
)

                plan.price = new_price
                plan.stripe_price_id = stripe_price.id

        if name is not None:
            plan.name = name

        if duration_days is not None:
            plan.duration_days = duration_days

        if max_agents is not None:
            plan.max_agents = max_agents

        if max_tickets is not None:
            plan.max_tickets = max_tickets

        if is_active is not None:
            plan.is_active = is_active

        plan.save()

        return {
            "data": {
                "id": plan.id,
                "name": plan.name,
                "price": str(plan.price),
                "duration_days": plan.duration_days,
                "max_agents": plan.max_agents,
                "max_tickets": plan.max_tickets,
                "stripe_product_id": plan.stripe_product_id,
                "stripe_price_id": plan.stripe_price_id,
                "is_active": plan.is_active,
                "created_at": plan.created_at.isoformat(),
            },
            "errors": {},
            "status": status.HTTP_200_OK
        }

    except Exception as e:
        traceback.print_exc()

        return {
            "data": None,
            "errors": {
                "details": str(e)
            },
            "status": status.HTTP_500_INTERNAL_SERVER_ERROR
        }