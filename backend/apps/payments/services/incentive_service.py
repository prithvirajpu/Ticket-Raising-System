from django.db.models import Avg
from .wallet_credit_service import credit_wallet
from decimal import Decimal
from django.utils import timezone
from apps.tickets.models import Ticket, TicketReview
from datetime import timedelta
from django.contrib.auth import get_user_model
User=get_user_model()

def calculate_agent_score(agent,month,year):

    resolved_count = Ticket.objects.filter(
        assigned_to=agent,
        status__in=["RESOLVED", "CLOSED"],
        updated_at__year=year,
        updated_at__month=month,
    ).count()

    escalated_count = Ticket.objects.filter(
        assigned_to=agent,
        status="ESCALATED",
        updated_at__year=year,
        updated_at__month=month
    ).count()

    avg_rating = TicketReview.objects.filter(
        ticket__assigned_to=agent,
        created_at__year=year,
        created_at__month=month
    ).aggregate(
        avg=Avg("rating")
    )["avg"] or 0

    score = (
        resolved_count * 10
        + avg_rating * 15
        - escalated_count * 20
    )

    return score

def get_best_agent():
    agents= User.objects.filter(role='AGENT',is_active=True)
    best_agent=None
    best_score=-1

    previous_month = (
            timezone.now().date().replace(day=1)
            - timedelta(days=1)
        )
    for agent in agents:
        score= calculate_agent_score(agent,previous_month.month,previous_month.year)
        if score>best_score:
            best_score=score
            best_agent=agent
    return best_agent

def reward_best_agent():
    best_agent=get_best_agent()

    if not best_agent:
        return
    credit_wallet(
        user=best_agent,
        amount=Decimal('1000.00'),
        transaction_type='INCENTIVE',
        description='Best Agent of the Month'
    )
    return best_agent