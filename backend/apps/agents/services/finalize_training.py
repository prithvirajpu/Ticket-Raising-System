from django.db import transaction
from apps.tickets.models import Ticket
from apps.accounts.models import User


def finalize_training(ticket):
    with transaction.atomic():

        assignment = (
            ticket.assignments
            .filter(status="ACCEPTED")
            .select_related("agent")
            .first()
        )

        if not assignment:
            return

        user = assignment.agent

        user.training_completed = True
        user.is_certified_agent = True

        user.save(update_fields=[
            "training_completed",
            "is_certified_agent"
        ])