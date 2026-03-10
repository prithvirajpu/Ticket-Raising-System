from tickets.models import Ticket

def create_ticket_service(data,user):
    print(data)
    print(user)
    ticket=Ticket.objects.create(
        subject=data.get('subject'),
        description=data.get('description'),
        client=user,
        created_by=user
    )
    return ticket