from rest_framework import serializers
from tickets.models import Ticket,TicketAssignment

class TicketSerializer(serializers.ModelSerializer):

    class Meta:
        model=Ticket
        fields=['id','subject','description','issue_type','priority']

class AgentTicketRequestSerializer(serializers.ModelSerializer):
    ticket_code = serializers.CharField(source="ticket.ticket_code")
    subject = serializers.CharField(source="ticket.subject")
    priority = serializers.CharField(source="ticket.priority")
    created_at = serializers.DateTimeField(source="ticket.created_at")

    class Meta:
        model=TicketAssignment
        fields=['id',"ticket_code","subject","priority","created_at","status",]