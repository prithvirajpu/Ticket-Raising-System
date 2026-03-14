def check_sla_breach_service():
    from django.utils import timezone
    from tickets.models import TicketSLATracking

    breached_slas= TicketSLATracking.objects.filter(sla_deadline__lt=timezone.now(), status='ON_TRACK')

    for sla in breached_slas:
        sla.sla_status='BREACHED'
        sla.save(update_fields=['status'])

        ticket=sla.ticket
        if ticket.status not in ['RESOLVED','CLOSED']:
            ticket.status='ESCALATED'
            ticket.save(update_fields=['status'])