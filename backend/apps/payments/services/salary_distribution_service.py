from datetime import datetime
from calendar import monthrange
from decimal import Decimal
import logging

from django.utils import timezone
from django.db import transaction
from django.contrib.auth import get_user_model

from apps.clients.models import ClientSubscription
from apps.payments.models import SalaryPayout

from .salary_service import (
    get_agent_ticket_counts,
    calculate_agent_salaries,
    get_salary_distribution_config,
    calculate_salary_pools,
    get_salary_eligible_team_leads,
    get_salary_eligible_managers,
    calculate_team_lead_salaries,
    calculate_manager_salaries,
    calculate_company_pool,
)

from .wallet_credit_service import credit_wallet
from .incentive_service import reward_best_agent


logger = logging.getLogger(__name__)

User = get_user_model()


def get_monthly_revenue(month_start, month_end):
    subscriptions = (
        ClientSubscription.objects
        .filter(
            start_date__lte=month_end,
            end_date__gte=month_start,
        )
        .select_related("plan")
    )

    revenue = Decimal("0")

    for subscription in subscriptions:
        revenue += subscription.plan.price

    return revenue

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

    days_in_month = monthrange(
        year,
        month
    )[1]

    month_start = timezone.make_aware(
        datetime(
            year,
            month,
            1
        )
    )

    month_end = timezone.make_aware(
        datetime(
            year,
            month,
            days_in_month,
            23,
            59,
            59
        )
    )

    # -----------------------------------------
    # Prevent duplicate salary distribution
    # -----------------------------------------

    already_paid = SalaryPayout.objects.filter(
        month=month,
        year=year
    ).exists()

    if already_paid:

        logger.info(
            "Salary already distributed for %s/%s",
            month,
            year
        )

        return {
            "message": "Already distributed"
        }

    # -----------------------------------------
    # Get monthly revenue
    # -----------------------------------------

    revenue = get_monthly_revenue(
    month_start.date(),
    month_end.date(),
)

    # -----------------------------------------
    # Get salary configuration
    # -----------------------------------------

    config = get_salary_distribution_config()

    # -----------------------------------------
    # Calculate all revenue pools
    # -----------------------------------------

    pools = calculate_salary_pools(
        revenue,
        config
    )

    agent_pool = pools["agent_pool"]
    incentive_pool = pools["incentive_pool"]
    team_lead_pool = pools["team_lead_pool"]
    manager_pool = pools["manager_pool"]

    # -----------------------------------------
    # Get eligible Team Leads
    # -----------------------------------------

    team_leads = get_salary_eligible_team_leads()

    # -----------------------------------------
    # Get eligible Managers
    # -----------------------------------------

    managers = get_salary_eligible_managers()

    # -----------------------------------------
    # Calculate Team Lead salaries
    # -----------------------------------------

    team_lead_salaries = calculate_team_lead_salaries(
        team_leads,
        team_lead_pool
    )

    # -----------------------------------------
    # Calculate Manager salaries
    # -----------------------------------------

    manager_salaries = calculate_manager_salaries(
        managers,
        manager_pool
    )
        # -----------------------------------------
    # Get agent ticket counts
    # -----------------------------------------

    ticket_counts = get_agent_ticket_counts(
        month_start,
        month_end
    )

    # -----------------------------------------
    # Calculate Agent salaries
    # -----------------------------------------

    agent_salaries = calculate_agent_salaries(
        agent_pool,
        ticket_counts
    )
    distributed_agent_amount = sum(
    agent_salaries.values(),
    Decimal("0")
)
    # -----------------------------------------
    # Calculate Company remainder
    # -----------------------------------------

    company_pool = calculate_company_pool(
        revenue=revenue,
        agent_pool=distributed_agent_amount,
        incentive_pool=incentive_pool,
        team_lead_pool=team_lead_pool,
        manager_pool=manager_pool,
    )

    # -----------------------------------------
    # Safety check
    # -----------------------------------------

    if company_pool < 0:

        raise ValueError(
            "Salary distribution cannot be completed because "
            "configured revenue shares exceed available revenue."
        )

    # -----------------------------------------
    # Company / Admin share
    # -----------------------------------------

    admin = User.objects.filter(
        role="ADMIN"
    ).first()

    if admin and company_pool > 0:

        credit_wallet(
            user=admin,
            amount=round(company_pool, 2),
            transaction_type="BONUS",
            description=(
                f"Company revenue share "
                f"({month}/{year})"
            ),
        )

    # -----------------------------------------
    # Agent salaries
    # -----------------------------------------

    for agent_id, salary in agent_salaries.items():

        agent = User.objects.filter(
            id=agent_id
        ).first()

        if not agent:
            continue

        credit_wallet(
            user=agent,
            amount=salary,
            transaction_type="SALARY",
            description=(
                f"Agent salary "
                f"({month}/{year})"
            ),
        )

    # -----------------------------------------
    # Team Lead salaries
    # -----------------------------------------

    for team_lead_id, salary in team_lead_salaries.items():

        team_lead = User.objects.filter(
            id=team_lead_id
        ).first()

        if not team_lead:
            continue

        credit_wallet(
            user=team_lead,
            amount=salary,
            transaction_type="SALARY",
            description=(
                f"Team Lead salary "
                f"({month}/{year})"
            ),
        )

    # -----------------------------------------
    # Manager salaries
    # -----------------------------------------

    for manager_id, salary in manager_salaries.items():

        manager = User.objects.filter(
            id=manager_id
        ).first()

        if not manager:
            continue

        credit_wallet(
            user=manager,
            amount=salary,
            transaction_type="SALARY",
            description=(
                f"Manager salary "
                f"({month}/{year})"
            ),
        )

    # -----------------------------------------
    # Incentive
    # -----------------------------------------

    if incentive_pool > 0:

        reward_best_agent(
            incentive_pool
        )

    # -----------------------------------------
    # Mark salary as processed
    # -----------------------------------------

    SalaryPayout.objects.create(
        month=month,
        year=year,
    )

    # -----------------------------------------
    # Return distribution summary
    # -----------------------------------------

    return {
        "revenue": revenue,

        "agent_pool": agent_pool,
        "incentive_pool": incentive_pool,
        "team_lead_pool": team_lead_pool,
        "manager_pool": manager_pool,

        "company_pool": company_pool,

        "agent_count": len(agent_salaries),
        "team_lead_count": len(team_lead_salaries),
        "manager_count": len(manager_salaries),
    }