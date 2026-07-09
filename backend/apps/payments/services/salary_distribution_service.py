from  decimal import Decimal
from datetime import datetime
from django.utils import timezone
from apps.clients.models import ClientSubscription
from apps.payments.models import SalaryPayout
from django.contrib.auth import get_user_model
from .wallet_credit_service import credit_wallet
from .incentive_service import reward_best_agent
from django.db import transaction
import logging
logger = logging.getLogger(__name__)

User = get_user_model()
from calendar import monthrange


@transaction.atomic
def get_monthly_revenue():
    active_subscriptions = ClientSubscription.objects.filter(
        status="ACTIVE"
    ).select_related("plan")

    revenue = Decimal("0")

    for subscription in active_subscriptions:
        revenue += subscription.plan.price
    return revenue

def calculate_salary_pools(revenue):
    return {
        "agent_pool": revenue * Decimal("0.25"),
        "tl_pool": revenue * Decimal("0.18"),
        "manager_pool": revenue * Decimal("0.10"),
        "company_pool": revenue * Decimal("0.42"),
        'incentive_pool':revenue * Decimal('0.05')
    }

@transaction.atomic
def distribute_monthly_salary():

    current_date = timezone.now()

    # Salary is for the previous month
    if current_date.month == 1:
        month = 12
        year = current_date.year - 1
    else:
        month = current_date.month - 1
        year = current_date.year

    days_in_month = monthrange(year, month)[1]

    month_start = timezone.make_aware(
        datetime(year, month, 1)
    )

    month_end = timezone.make_aware(
        datetime(year, month, days_in_month, 23, 59, 59)
    )

    already_paid = SalaryPayout.objects.filter(
        month=month,
        year=year
    ).exists()

    if already_paid:
        logger.info("Salary already distributed for %s/%s", month, year)
        return {"message": "Already distributed"}

    revenue = get_monthly_revenue()
    pools = calculate_salary_pools(revenue)

    agents = User.objects.filter(
        role="AGENT",
        is_active=True,
        is_certified_agent=True,
    )

    tls = User.objects.filter(
        role="TEAM_LEAD",
        is_active=True,
    )

    managers = User.objects.filter(
        role="MANAGER",
        is_active=True,
    )

    admin = User.objects.filter(role="ADMIN").first()

    agent_count = agents.count()
    tl_count = tls.count()
    manager_count = managers.count()

    # Company Share
    if admin:
        credit_wallet(
            user=admin,
            amount=pools["company_pool"],
            transaction_type="BONUS",
            description=f"Company revenue share ({month}/{year})",
        )

    # Agent Salary
    if agent_count:
        base_salary = pools["agent_pool"] / agent_count

        for agent in agents:

            if not agent.certified_at:
                continue

            certified_date = timezone.localtime(agent.certified_at)

            # Certified after salary month
            if certified_date > month_end:
                worked_days = 0

            # Certified before salary month
            elif certified_date < month_start:
                worked_days = days_in_month

            # Certified during salary month
            else:
                worked_days = days_in_month - certified_date.day + 1

            if worked_days == 0:
                continue

            salary = (
                base_salary
                * Decimal(worked_days)
                / Decimal(days_in_month)
            )

            credit_wallet(
                user=agent,
                amount=round(salary, 2),
                transaction_type="SALARY",
                description=f"Salary distribution",
            )

    # Team Leads
    if tl_count:
        tl_share = round(pools["tl_pool"] / tl_count, 2)

        for tl in tls:
            credit_wallet(
                user=tl,
                amount=tl_share,
                transaction_type="SALARY",
                description=f"Salary Share Distribution ({month}/{year})",
            )

    # Managers
    if manager_count:
        manager_share = round(pools["manager_pool"] / manager_count, 2)

        for manager in managers:
            credit_wallet(
                user=manager,
                amount=manager_share,
                transaction_type="SALARY",
                description=f"Salary Share Distribution ({month}/{year})",
            )

    # Incentive
    reward_best_agent(pools["incentive_pool"])

    SalaryPayout.objects.create(
        month=month,
        year=year,
    )

    return {
        "revenue": revenue,
        "agent_count": agent_count,
        "tl_count": tl_count,
        "manager_count": manager_count,
    }