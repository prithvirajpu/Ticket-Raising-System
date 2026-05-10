from rest_framework import serializers
from apps.tickets.models import TicketActivity

class TicketActivitySerializer(serializers.ModelSerializer):
    performed_by= serializers.StringRelatedField()

    class Meta:
        model= TicketActivity
        fields= '__all__'