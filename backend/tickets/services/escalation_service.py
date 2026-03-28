from tickets.models import Ticket
from rest_framework import status

def escalate_ticket_service(request,ticket_id):
    user=request.user
    ticket= Ticket.objects.filter(id=ticket_id).first()

    if not ticket:
        return {
            "data": None,
            "errors": {"details": "Ticket not found"},
            "status": status.HTTP_404_NOT_FOUND
        }
    if ticket.assigned_to !=user:
        return {
            "data": None,
            "errors": {"details": "Not allowed"},
            "status": status.HTTP_403_FORBIDDEN
        }
    if ticket.client.user.team_lead!=user.team_lead:
        return{
            "data": None,
            "errors": {"details": "Invalid team access"},
            "status": status.HTTP_403_FORBIDDEN
        }
    if ticket.status!='IN_PROGRESS':
        return {
            "data": None,
            "errors": {"details": "Only in-progress tickets can be escalated"},
            "status": status.HTTP_400_BAD_REQUEST
        }
    if ticket.status=='ESCALATED':
        return {
            "data": None,
            "errors": {"details": "Ticket already escalated"},
            "status": status.HTTP_400_BAD_REQUEST
        }
    team_lead=ticket.client.team_lead
    if not team_lead:
        return {
            "data": None,
            "errors": {"details": "No team lead assigned to this client."},
            "status": status.HTTP_404_NOT_FOUND
        }
    ticket.status='ESCALATED'
    ticket.assigned_to=team_lead
    ticket.save(update_fields=['status','assigned_to'])
    return {
        "data": {'message':'Escalated to team lead'},
        "errors": {},
        "status": status.HTTP_200_OK
    }
