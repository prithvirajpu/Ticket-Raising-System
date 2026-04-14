def auto_assign_service():
    from django.utils import timezone
    from django.db import transaction
    from tickets.models import TicketAssignment, Ticket
    from tickets.utils import get_next_available_agent
    import logging
    logger = logging.getLogger(__name__)

    logger.info("AUTO ASSIGN SERVICE TRIGGERED")
    


    expired_assignments = TicketAssignment.objects.filter(
        status="PENDING",
        expires_at__lt=timezone.now()
    )
    logger.info(f"Expired count: {expired_assignments.count()}")

    print("EXPIRED FOUND:", expired_assignments.count())

    for assignment in expired_assignments:

        with transaction.atomic():

            # lock fresh row
            assignment = TicketAssignment.objects.select_for_update().get(id=assignment.id)
            ticket = Ticket.objects.select_for_update().get(id=assignment.ticket_id)

            # safety check
            if ticket.assigned_to_id:
                continue

            print("Processing assignment:", assignment.id)

            assignment.status = "EXPIRED"
            assignment.save(update_fields=["status"])

            agent = get_next_available_agent(ticket)

            print("Selected agent:", agent)

            if not agent:
                continue

            ticket.assigned_to = agent
            ticket.status = "IN_PROGRESS"
            ticket.save(update_fields=["assigned_to", "status"])

            TicketAssignment.objects.create(
                ticket=ticket,
                agent=agent,
                status="ACCEPTED"
            )

            print("🔥 AUTO ASSIGNED:", ticket.id, "->", agent.id)