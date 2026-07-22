from django.db import models
from django.contrib.auth import get_user_model
from apps.clients.models import ClientProfile

User=get_user_model()

class Notification(models.Model):

    NOTIFICATION_TYPES = (
        ("WELCOME_ACCOUNT_CREATED", "welcome account created"),
        ("TICKET_ASSIGNED", "Ticket Assigned"),
        ("TICKET_ESCALATED", "Ticket Escalated"),
        ("TICKET_RESOLVED", "Ticket Resolved"),
        ("MISSED_CALL", "Missed Call"),
        ("TICKET_REOPENED", "ticket reopened"),
        ("CHAT_MESSAGE", "Chat Message"),
    )
    user = models.ForeignKey(User,on_delete=models.CASCADE,related_name="notifications")
    client = models.ForeignKey(
        ClientProfile,
        on_delete=models.CASCADE,related_name="notifications",null=True,blank=True
    )

    notification_type = models.CharField(max_length=50,choices=NOTIFICATION_TYPES)
    title = models.CharField(max_length=255)
    message = models.TextField()
    data = models.JSONField(default=dict,blank=True)
    is_read = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-created_at"]