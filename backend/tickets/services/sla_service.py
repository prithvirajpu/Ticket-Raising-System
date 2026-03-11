from tickets.models import ClientSubscription,SLAPolicy,TicketSLATracking
from datetime import timedelta
from django.utils import timezone


def attach_sla_to_ticket(ticket):
    subscription=ClientSubscription.objects.filter(client=ticket.client,status='ACTIVE').first()
    if not subscription:
        return None
    sla_policy=SLAPolicy.objects.filter(plan=subscription.plan,priority=ticket.priority,is_active=True).first()

    if not sla_policy:
        return None
    
    deadline=timezone.now()+ timedelta(
        minutes=sla_policy.resolution_time_minutes
    )
    TicketSLATracking.objects.create(ticket=ticket,sla_policy=sla_policy,sla_deadline=deadline)