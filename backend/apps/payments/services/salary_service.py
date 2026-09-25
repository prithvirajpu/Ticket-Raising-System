from decimal import Decimal

from django.contrib.auth import get_user_model
from django.db.models import Count

from apps.payments.models import SalaryDistributionConfig
from apps.tickets.models import Ticket


User = get_user_model()


def get_agent_ticket_counts(
    month_start,
    month_end
):

    agents = User.objects.filter(
        role="AGENT",
        is_active=True,
        is_certified_agent=True,
    )

    ticket_counts = (
        Ticket.objects
        .filter(
            assigned_to__in=agents,
            status="CLOSED",
            closed_at__gte=month_start,
            closed_at__lte=month_end,
            is_training_ticket=False,
        )
        .values("assigned_to")
        .annotate(
            ticket_count=Count("id")
        )
    )

    return {
        item["assigned_to"]: item["ticket_count"]
        for item in ticket_counts
    }


def calculate_agent_salaries(
    agent_pool,
    ticket_counts,
):

    total_tickets = sum(
        ticket_counts.values()
    )

    if total_tickets == 0:
        return {}

    salaries = {}

    for agent_id, ticket_count in ticket_counts.items():

        salary = (
            agent_pool
            * Decimal(ticket_count)
            / Decimal(total_tickets)
        )

        salaries[agent_id] = round(
            salary,
            2
        )

    return salaries


def get_salary_distribution_config():

    config = SalaryDistributionConfig.objects.filter(
        is_active=True
    ).first()

    if not config:
        raise ValueError(
            "Salary distribution configuration not found."
        )

    return config


def calculate_salary_pools(
    revenue,
    config,
):

    agent_pool = (
        revenue
        * config.agent_percentage
        / Decimal("100")
    )

    incentive_pool = (
        revenue
        * config.incentive_percentage
        / Decimal("100")
    )

    team_lead_pool = (
        revenue
        * config.team_lead_percentage
        / Decimal("100")
    )

    manager_pool = (
        revenue
        * config.manager_percentage
        / Decimal("100")
    )

    return {
        "agent_pool": agent_pool,
        "incentive_pool": incentive_pool,
        "team_lead_pool": team_lead_pool,
        "manager_pool": manager_pool,
    }


def get_salary_eligible_team_leads():

    return User.objects.filter(
        role="TEAM_LEAD",
        is_active=True,
        clients__isnull=False,
    ).distinct()


def get_salary_eligible_managers():

    return User.objects.filter(
        role="MANAGER",
        is_active=True,
    )


def calculate_team_lead_salaries(
    team_leads,
    team_lead_pool,
):

    team_lead_count = team_leads.count()

    if team_lead_count == 0:
        return {}

    salary_per_team_lead = (
        team_lead_pool
        / Decimal(team_lead_count)
    )

    return {
        team_lead.id: round(
            salary_per_team_lead,
            2
        )
        for team_lead in team_leads
    }


def calculate_manager_salaries(
    managers,
    manager_pool,
):

    manager_count = managers.count()

    if manager_count == 0:
        return {}

    salary_per_manager = (
        manager_pool
        / Decimal(manager_count)
    )

    return {
        manager.id: round(
            salary_per_manager,
            2
        )
        for manager in managers
    }


def calculate_company_pool(
    revenue,
    agent_pool,
    incentive_pool,
    team_lead_pool,
    manager_pool,
):

    return (
        revenue
        - agent_pool
        - incentive_pool
        - team_lead_pool
        - manager_pool
    )