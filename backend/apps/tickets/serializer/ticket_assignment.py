from apps.tickets.models import TicketAssignment
from apps.tickets.serializer import TicketSerializer
from rest_framework import serializers

class TicketAssignmentSerializer(serializers.ModelSerializer):
    ticket = TicketSerializer(read_only=True)

    class Meta:
        model = TicketAssignment
        fields = [
            "id",
            "status",
            "training_status",
            "training_score",
            "training_passed",
            "training_feedback",
            "ticket",
        ]