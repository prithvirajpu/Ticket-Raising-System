from django.utils import timezone
from tickets.models import TicketSLATracking
from django.db import transaction

def run_sla_check():
    now=timezone.now()

    sla_records= TicketSLATracking.objects.select_related('ticket','sla_policy'
                                                          ).filter(sla_status='ON_TRACK',resolved_at__isnull=True)
    
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
    from tickets.utils import get_next_available_agent

    new_agent = get_next_available_agent(ticket)

    if not new_agent:
        return

    ticket.assigned_to = new_agent
    ticket.status = "IN_PROGRESS"
    ticket.save(update_fields=["assigned_to", "status"])

    sla.reassign_count += 1
    sla.save(update_fields=["reassign_count"])
     
