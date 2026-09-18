import stripe
import traceback
import logging
from decimal import Decimal
from django.conf import settings
from rest_framework import status

from apps.clients.models import SubscriptionPlan

logger = logging.getLogger(__name__)

stripe.api_key = settings.STRIPE_SECRET_KEY


def create_subscription_plan_service(data):
    try:
        name = data.get("name")
        price = data.get("price")
        duration_days = data.get("duration_days")
        max_agents = data.get("max_agents")
        max_tickets = data.get("max_tickets")

        if not name:
            return {
                "data": None,
                "errors": {
                    "details": "Plan name is required"
                },
                "status": status.HTTP_400_BAD_REQUEST
            }

        if price is None:
            return {
                "data": None,
                "errors": {
                    "details": "Plan price is required"
                },
                "status": status.HTTP_400_BAD_REQUEST
            }

        if duration_days is None:
            return {
                "data": None,
                "errors": {
                    "details": "Duration is required"
                },
                "status": status.HTTP_400_BAD_REQUEST
            }

        if max_agents is None:
            return {
                "data": None,
                "errors": {
                    "details": "Maximum agents is required"
                },
                "status": status.HTTP_400_BAD_REQUEST
            }

        if max_tickets is None:
            return {
                "data": None,
                "errors": {
                    "details": "Maximum tickets is required"
                },
                "status": status.HTTP_400_BAD_REQUEST
            }
        try:
            price = Decimal(str(price))
            duration_days = int(duration_days)
            max_agents = int(max_agents)
            max_tickets = int(max_tickets)
        except (ValueError, TypeError, ArithmeticError):
            return {
                "data": None,
                "errors": {
                    "details": "Invalid plan values"
                },
                "status": status.HTTP_400_BAD_REQUEST
            }

        if price <= 0:
            return {
                "data": None,
                "errors": {
                    "details": "Price must be greater than 0"
                },
                "status": status.HTTP_400_BAD_REQUEST
            }

        if duration_days <= 0:
            return {
                "data": None,
                "errors": {
                    "details": "Duration must be greater than 0"
                },
                "status": status.HTTP_400_BAD_REQUEST
            }

        if max_agents <= 0:
            return {
                "data": None,
                "errors": {
                    "details": "Maximum agents must be greater than 0"
                },
                "status": status.HTTP_400_BAD_REQUEST
            }

        if max_tickets <= 0:
            return {
                "data": None,
                "errors": {
                    "details": "Maximum tickets must be greater than 0"
                },
                "status": status.HTTP_400_BAD_REQUEST
            }

        product = stripe.Product.create(
            name=name,
            metadata={
                "duration_days": str(duration_days),
                "max_agents": str(max_agents),
                "max_tickets": str(max_tickets),
            }
        )
        stripe_price = stripe.Price.create(
            product=product.id,
            unit_amount=int(Decimal(str(price)) * 100),
            currency="inr",
            recurring={
                "interval": "month"
            }
        )

        plan = SubscriptionPlan.objects.create(
            name=name,
            price=price,
            duration_days=duration_days,
            max_agents=max_agents,
            max_tickets=max_tickets,
            stripe_product_id=product.id,
            stripe_price_id=stripe_price.id,
            is_active=True
        )

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
            },
            "errors": {},
            "status": status.HTTP_201_CREATED
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


def get_subscription_plans_service():
    try:
        plans = SubscriptionPlan.objects.all().order_by("-created_at")

        data = []

        for plan in plans:
            data.append({
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
            })

        return {
            "data": data,
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