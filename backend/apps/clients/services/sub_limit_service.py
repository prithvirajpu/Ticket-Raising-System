from rest_framework import status
from apps.clients.models import ClientSubscription
from apps.tickets.models import Ticket
from django.contrib.auth import get_user_model
User=get_user_model()
import logging
logger=logging.getLogger()

def get_active_subscription(client):
    subscription=(ClientSubscription.objects.select_related('plan').filter(
        client=client,status__in=['ACTIVE','CANCEL_SCHEDULED']
    ).first())
    if not subscription:
        return None
    return subscription

def check_ticket_limit(client):
    subscription=get_active_subscription(client)
    if not subscription:
        return {
            "allowed": False,
            "message": "No active subscription found."
        }
    current_ticket_count=Ticket.objects.filter(client=client).count()
    if current_ticket_count >= subscription.plan.max_tickets:
        return {
            "allowed": False,
            "message": (
                f"Ticket limit reached. "
                f"Your {subscription.plan.name} allows "
                f"a maximum of {subscription.plan.max_tickets} tickets."
            )
        }
    return {
        "allowed": True,
        "remaining": (
            subscription.plan.max_tickets -
            current_ticket_count
        )
    }

def check_agent_limit(client, exclude_user_id=None):
    subscription = get_active_subscription(client)
    logger.info("SUBSCRIPTION = %s", subscription)
    logger.info("MAX AGENTS = %s", subscription.plan.max_agents if subscription else None)

    if not subscription:
        return {
            "allowed": False,
            "message": "No active subscription found."
        }

    team_lead = client.team_lead

    queryset = User.objects.filter(
        role="AGENT",
        team_lead=team_lead,
        is_active=True
    )

    if exclude_user_id:
        queryset = queryset.exclude(id=exclude_user_id)
        logger.info("EXCLUDE USER = %s", exclude_user_id)
    logger.info(
    "AGENTS = %s",
    list(queryset.values_list("id", "email"))
)
    current_agent_count = queryset.count()
    logger.info("CURRENT COUNT = %s", current_agent_count)

    if current_agent_count >= subscription.plan.max_agents:
        return {
            "allowed": False,
            "message": (
                f"Agent limit reached. "
                f"Your {subscription.plan.name} allows only "
                f"{subscription.plan.max_agents} agents."
            )
        }

    return {
        "allowed": True,
        "remaining": subscription.plan.max_agents - current_agent_count
    }