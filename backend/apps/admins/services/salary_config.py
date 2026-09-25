from django.db import transaction
from apps.payments.models import SalaryDistributionConfig


@transaction.atomic
def create_salary_config(data):

    agent_percentage = data["agent_percentage"]
    incentive_percentage = data["incentive_percentage"]
    team_lead_percentage = data["team_lead_percentage"]
    manager_percentage = data["manager_percentage"]

    total_percentage = (
        agent_percentage
        + incentive_percentage
        + team_lead_percentage
        + manager_percentage
    )

    if total_percentage > 100:
        return {
            "data": None,
            "errors": {
                "percentage": (
                    "Agent, incentive, team lead and manager "
                    "percentages cannot exceed 100% together."
                )
            },
            "status": 400
        }

    SalaryDistributionConfig.objects.filter(
        is_active=True
    ).update(is_active=False)

    config = SalaryDistributionConfig.objects.create(
        **data,
        is_active=True
    )

    return {
        "data": config,
        "errors": None,
        "status": 201
    }


def get_salary_config():

    config = SalaryDistributionConfig.objects.filter(
        is_active=True
    ).first()

    if not config:
        return {
            "data": None,
            "errors": {
                "details": "Salary configuration not found."
            },
            "status": 404
        }

    return {
        "data": config,
        "errors": None,
        "status": 200
    }


@transaction.atomic
def update_salary_config(data):

    config = SalaryDistributionConfig.objects.filter(
        is_active=True
    ).first()

    if not config:
        return {
            "data": None,
            "errors": {
                "details": "Salary configuration not found."
            },
            "status": 404
        }

    agent_percentage = data.get(
        "agent_percentage",
        config.agent_percentage
    )

    incentive_percentage = data.get(
        "incentive_percentage",
        config.incentive_percentage
    )

    team_lead_percentage = data.get(
        "team_lead_percentage",
        config.team_lead_percentage
    )

    manager_percentage = data.get(
        "manager_percentage",
        config.manager_percentage
    )

    total_percentage = (
        agent_percentage
        + incentive_percentage
        + team_lead_percentage
        + manager_percentage
    )

    if total_percentage > 100:
        return {
            "data": None,
            "errors": {
                "percentage": (
                    "Agent, incentive, team lead and manager "
                    "percentages cannot exceed 100% together."
                )
            },
            "status": 400
        }

    for field in [
        "agent_percentage",
        "incentive_percentage",
        "team_lead_percentage",
        "manager_percentage",
    ]:
        if field in data:
            setattr(
                config,
                field,
                data[field]
            )

    config.save()

    return {
        "data": config,
        "errors": None,
        "status": 200
    }