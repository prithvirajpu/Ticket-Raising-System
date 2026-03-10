from rest_framework import serializers
from tickets.models import Ticket

class TicketSerializer(serializers.ModelSerializer):

    class Meta:
        model=Ticket
        fields=['subject','description','issue_type','priority']