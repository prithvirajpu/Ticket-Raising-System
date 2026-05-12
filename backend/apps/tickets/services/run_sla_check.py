from django.utils import timezone
from apps.tickets.models import TicketSLATracking,Ticket
from django.db import transaction

import traceback
import logging
logger= logging.getLogger(__name__)

def assign_ticket(ticket, agent, reason=None):
    print("\n🔥 ASSIGN_TICKET CALLED")
    print("Ticket:", ticket.id)
    print("Agent:", agent.id if agent else None)
    print("Reason:", reason)

    print("CALL STACK:")
    traceback.print_stack()
    from apps.tickets.models import TicketAssignment

    with transaction.atomic():
        ticket = Ticket.objects.select_for_update().get(id=ticket.id)

        # 🔒 safety check
        if ticket.assigned_to:
            return

        ticket.assigned_to = agent
        ticket.status = "IN_PROGRESS"
        ticket.save(update_fields=["assigned_to", "status"])

        TicketAssignment.objects.create(
            ticket=ticket,
            agent=agent,
            status="ACCEPTED"
        )

def run_sla_check():
    now=timezone.now()

    sla_records= TicketSLATracking.objects.select_related('ticket','sla_policy'
                                                          ).filter(sla_status='ON_TRACK',resolved_at__isnull=True,ticket__status="OPEN")
    
    for sla in sla_records:
        if sla.sla_deadline<now:
            handle_sla_breach(sla)

def handle_sla_breach(sla):
    policy=sla.sla_policy
    ticket=sla.ticket

    with transaction.atomic():
        sla.sla_status='BREACHED'
        sla.breach_reason='Resolution time exceeded'
        sla.save(update_fields=['sla_status','breach_reason'])

        if (policy and policy.auto_reassign and sla.reassign_count < policy.max_reassign_attempts):
            reassign_ticket(ticket,sla)

def reassign_ticket(ticket, sla):
    from apps.tickets.utils import get_next_available_agent

    # 🔒 prevent double SLA + auto assignment conflict
    ticket.refresh_from_db()
    if ticket.status == "IN_PROGRESS":
        return

    new_agent = get_next_available_agent(ticket)

    if not new_agent:
        return

    assign_ticket(ticket, new_agent, reason="SLA_REASSIGN")

    sla.reassign_count += 1
    sla.save(update_fields=["reassign_count"])
