from  decimal import Decimal
from django.utils import timezone
from apps.clients.models import ClientSubscription
from apps.payments.models import SalaryPayout
from django.contrib.auth import get_user_model
from .wallet_credit_service import credit_wallet
from .incentive_service import reward_best_agent
import logging
logger = logging.getLogger(__name__)

User = get_user_model()

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
        "company_pool": revenue * Decimal("0.47")
    }

def distribute_monthly_salary():
    current_date= timezone.now()
    month=current_date.month
    year=current_date.year
    already_paid= SalaryPayout.objects.filter(
        month=month,year=year
    ).exists()
    if already_paid:
        raise Exception(f'Salary already distributed for {month}/{year}')

    revenue = get_monthly_revenue()
    pools = calculate_salary_pools(revenue)

    agents = User.objects.filter(
        role="AGENT",
        is_active=True
    )

    tls = User.objects.filter(
        role="TEAM_LEAD",
        is_active=True
    )

    managers = User.objects.filter(
        role="MANAGER",
        is_active=True
    )

    agent_count = agents.count()
    tl_count = tls.count()
    manager_count = managers.count()

    if agent_count:
        agent_share = round(pools["agent_pool"] / agent_count,2)

        for agent in agents:
            credit_wallet(
                user=agent,
                amount=agent_share,
                transaction_type="SALARY",
                description="Monthly salary distribution"
            )

    if tl_count:
        tl_share = round(pools["tl_pool"] / tl_count,2)

        for tl in tls:
            credit_wallet(
                user=tl,
                amount=tl_share,
                transaction_type="SALARY",
                description="Monthly salary distribution"
            )

    if manager_count:
        manager_share = round(pools["manager_pool"] / manager_count,2)

        for manager in managers:
            credit_wallet(
                user=manager,
                amount=manager_share,
                transaction_type="SALARY",
                description="Monthly salary distribution"
            )
    reward_best_agent()
    SalaryPayout.objects.create(month=month,year=year)

    return {
        "revenue": revenue,
        "agent_count": agent_count,
        "tl_count": tl_count,
        "manager_count": manager_count,
    }