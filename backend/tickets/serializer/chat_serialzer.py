from rest_framework import serializers
from tickets.models import TicketChat

class TicketChatSerializer(serializers.ModelSerializer):
    sender_name=serializers.CharField(source='sender.username',read_only=True)

    class Meta:
        model=TicketChat
        fields=['id','ticket','sender','sender_name','message','message_type','created_at']
        read_only_fields=['sender','created_at']