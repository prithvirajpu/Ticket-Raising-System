from django.db import models
from apps.tickets.models import TicketAssignment

class TrainingConversation(models.Model):
    assignment = models.ForeignKey(
        TicketAssignment,
        on_delete=models.CASCADE,
        related_name='training_messages'
    )

    sender_type = models.CharField(
        max_length=20,
        choices=[
            ('AGENT', 'Agent'),
            ('AI_CUSTOMER', 'AI Customer')
        ]
    )

    message = models.TextField()

    created_at = models.DateTimeField(auto_now_add=True)