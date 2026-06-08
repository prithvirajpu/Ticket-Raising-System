def auto_assign_service():
    from django.utils import timezone
    from django.db import transaction
    from apps.tickets.models import TicketAssignment, Ticket,TicketActivity
    from apps.tickets.utils.next_available_agent import get_next_available_agent
    from apps.tickets.utils import send_notification
    import logging
    logger = logging.getLogger(__name__)

    logger.info("AUTO ASSIGN SERVICE TRIGGERED")

    expired_assignments = TicketAssignment.objects.filter(
        status="PENDING",
        expires_at__lt=timezone.now()
    )
    logger.info(f"Expired count: {expired_assignments.count()}")

    for assignment in expired_assignments:

        with transaction.atomic():

            assignment = TicketAssignment.objects.select_for_update().get(id=assignment.id)
            ticket = Ticket.objects.select_for_update().get(id=assignment.ticket_id)

            # safety check
            if ticket.assigned_to_id:
                continue

            assignment.status = "EXPIRED"
            assignment.save(update_fields=["status"])

            agent = get_next_available_agent(ticket)

            if not agent:
                continue

            ticket.assigned_to = agent
            ticket.status = "IN_PROGRESS"
            ticket.save(update_fields=["assigned_to", "status"])
            send_notification(
                user_id=agent.id,
                notification_type="TICKET_ASSIGNED",
                title="New Ticket Assigned",
                message=f"Ticket #{ticket.ticket_code} has been auto-assigned to you",
                data={
                    "ticket_id": ticket.id,
                    "ticket_code": ticket.ticket_code,
                }
            )
            TicketAssignment.objects.filter(
                    ticket=ticket,
                    agent=agent,
                    status="PENDING"
                ).update(status="ACCEPTED")
            
            TicketAssignment.objects.filter(
                    ticket=ticket,
                    status="PENDING"
                ).exclude(agent=agent).update(status="CANCELLED")
            from apps.tickets.models import TicketChatParticipant

            TicketChatParticipant.objects.get_or_create(
                        ticket=ticket,
                        user=ticket.created_by,
                        defaults={"role": "USER"}
                    )

            TicketChatParticipant.objects.get_or_create(
                        ticket=ticket,
                        user=agent,
                        defaults={"role": "AGENT"}
                    )

            TicketActivity.objects.create(
                ticket=ticket,
                action="AUTO_ASSIGNED",
                performed_by=agent,
                description=f"Ticket auto assigned to agent"
            )