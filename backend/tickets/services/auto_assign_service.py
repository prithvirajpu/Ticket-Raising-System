from django.db.models import Count, Q
from django.utils import timezone
from django.db import transaction
from tickets.models import TicketAssignment,Ticket
from django.contrib.auth import get_user_model

User = get_user_model()

def auto_assign_service():

    expired_ticket_ids = TicketAssignment.objects.filter(
        status="PENDING",
        expires_at__lt=timezone.now()
    ).values_list("ticket_id", flat=True).distinct()

    for ticket_id in expired_ticket_ids:

        with transaction.atomic():

            TicketAssignment.objects.filter(
                ticket_id=ticket_id,
                status="PENDING"
            ).update(status="EXPIRED")

            ticket = Ticket.objects.select_for_update().get(id=ticket_id)

            if ticket.assigned_to:
                continue

            agents_who_received = TicketAssignment.objects.filter(
                ticket_id=ticket_id
            ).values_list("agent_id", flat=True)

            least_busy_agent = User.objects.filter(
                role="AGENT",
                is_active=True
            ).exclude(
                id__in=agents_who_received
            ).annotate(
                active_tickets=Count(
                    "assigned_tickets",
                    filter=Q(assigned_tickets__status="IN_PROGRESS")
                )
            ).order_by("active_tickets").first()

            if not least_busy_agent:
                continue

            ticket.assigned_to = least_busy_agent
            ticket.status = "IN_PROGRESS"
            ticket.save(update_fields=["assigned_to", "status"])

            TicketAssignment.objects.filter(
                ticket=ticket
            ).update(status="CANCELLED")