from django.db import transaction
from apps.tickets.models import Ticket,TicketAssignment,TicketSLATracking,TicketChatParticipant,TicketActivity
from rest_framework import status
from django.utils import timezone


def resolve_ticket_service(user,ticket_id):
    try:
        with transaction.atomic():
            ticket=Ticket.objects.filter(id=ticket_id,assigned_to=user).first()
            if not ticket:
                return {
                    "data": None,
                    "errors": {"details": "Ticket not assigned to this agent"},
                    "status": status.HTTP_403_FORBIDDEN
                }
            if ticket.status not in ['IN_PROGRESS','ESCALATED']:
                return {
                    "data": None,
                    "errors": {"details": "Ticket is not in progress"},
                    "status": status.HTTP_400_BAD_REQUEST
                }
            ticket.status='RESOLVED'
            ticket.save(update_fields=['status'])
            TicketActivity.objects.create(
                ticket=ticket,
                action="RESOLVED",
                performed_by=user,
                description="Ticket marked as resolved"
            )

            sla = getattr(ticket, 'sla_tracking', None)
            if sla:
                now = timezone.now()
                sla.resolved_at = now
                sla.sla_status = 'MET' if now <= sla.sla_deadline else 'BREACHED'
                sla.save(update_fields=['sla_status', 'resolved_at'])

            return {
                "data": {"message": "Ticket resolved successfully"},
                "errors": {},
                "status": status.HTTP_200_OK
            }
    except Exception as e:
        return {
            "data": None,
            "errors": {"details": str(e)},
            "status": status.HTTP_500_INTERNAL_SERVER_ERROR
        }