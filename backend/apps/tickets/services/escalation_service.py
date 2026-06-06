from apps.tickets.models import Ticket,TicketActivity,Notification
from rest_framework import status
from django.utils import timezone
from apps.tickets.utils import send_notification


def escalate_ticket_service(user, ticket_id):
    ticket = Ticket.objects.filter(id=ticket_id).first()

    if not ticket:
        return {
            "data": None,
            "errors": {"details": "Ticket not found"},
            "status": status.HTTP_404_NOT_FOUND
        }

    if ticket.assigned_to_id != user.id:
        return {
            "data": None,
            "errors": {"details": "Not allowed"},
            "status": status.HTTP_403_FORBIDDEN
        }

    if ticket.status not in ['IN_PROGRESS', 'ESCALATED']:
        return {
            "data": None,
            "errors": {"details": "Only active tickets can be escalated"},
            "status": status.HTTP_400_BAD_REQUEST
        }

    # 🔥 ROLE-BASED ESCALATION
    next_assignee = None

    if user.role == "AGENT":
        next_assignee = user.team_lead

    elif user.role == "TEAM_LEAD":
        next_assignee = user.manager

    elif user.role == "MANAGER":
        return {
            "data": None,
            "errors": {"details": "Manager cannot escalate further"},
            "status": status.HTTP_400_BAD_REQUEST
        }

    if not next_assignee:
        return {
            "data": None,
            "errors": {"details": "No higher authority assigned"},
            "status": status.HTTP_400_BAD_REQUEST
        }

    ticket.status = "ESCALATED"
    ticket.assigned_to = next_assignee
    from apps.tickets.models import TicketChatParticipant
    TicketChatParticipant.objects.get_or_create(
            ticket=ticket,
            user=next_assignee
        )
    ticket.save(update_fields=["status", "assigned_to"])
    send_notification(user_id=next_assignee.id,
            notification_type="TICKET_ESCALATED",
            title="Ticket Escalated",
            message=f"Ticket #{ticket.id} has been escalated to you",
            data={"ticket_id": ticket.id}   
            )
    notification= Notification.objects.create(
        user_id=next_assignee.id,
        notification='TICKET_ESCALATED',
        title="Ticket Escalated",
        message=f"Ticket #{ticket.id} has been escalated to you",
        data={"ticket_id": ticket.id} 


    )
    TicketActivity.objects.create(
        ticket=ticket,
        action="ESCALATED",
        performed_by=user,
        description="Ticket escalated to higher authority"
    )

    return {
        "data": {"message": f"Escalated to {next_assignee.role}"},
        "errors": {},
        "status": status.HTTP_200_OK
    }
