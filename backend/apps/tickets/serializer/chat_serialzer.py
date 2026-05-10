from rest_framework import serializers
from apps.tickets.models import TicketChat

class TicketChatSerializer(serializers.ModelSerializer):
    sender_id = serializers.IntegerField(source="sender.id", read_only=True)
    sender_name = serializers.CharField(source="sender.email", read_only=True)

    class Meta:
        model = TicketChat
        fields = [
            "id",
            "ticket",
            "message",
            "message_type",
            "is_deleted",
            "created_at",
            "sender_id",
            "sender_name",
        ]
    def get_sender_name(self, obj):
        return getattr(obj.sender, "email", None) or getattr(obj.sender, "username", "")