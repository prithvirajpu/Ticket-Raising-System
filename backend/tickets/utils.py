from django.contrib.auth import get_user_model
from django.db.models import Count, Q

User = get_user_model()


def get_next_available_agent(ticket):

    agents = User.objects.filter(
        role='AGENT',
        is_active=True
    ).exclude(
        id=ticket.assigned_to_id
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

    return agents.first()