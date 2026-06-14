from django.contrib.auth import get_user_model
from apps.tickets.models import TicketAssignment
from django.db.models import Count, Q

from asgiref.sync import async_to_sync
from channels.layers import get_channel_layer

User = get_user_model()
import logging
logger=logging.getLogger(__name__)


def get_next_available_agent(ticket):
    
    rejected_agent_ids = TicketAssignment.objects.filter(
        ticket=ticket,
        status="REJECTED"
    ).values_list("agent_id", flat=True)

    agents = User.objects.filter(
        role='AGENT',
        is_active=True,
        is_certified_agent=True
    ).exclude(
        id=ticket.assigned_to_id
    ).exclude(
        id__in=rejected_agent_ids
    ).annotate(
        active_tickets=Count(
            'assigned_tickets',
            filter=Q(
                assigned_tickets__status__in=[
                    'OPEN', 'IN_PROGRESS', 'ESCALATED'
                ]
            )
        )
    ).order_by('active_tickets', 'id')
    agent = agents.first()
    logger.info(f"Rejected agents: {list(rejected_agent_ids)}")
    logger.info(f"Selected agent: {agent}")
    return agents.first()

