from django.db import models
from django.contrib.auth import get_user_model

User=get_user_model()

class TicketChat(models.Model):
    MESSAGE_TYPE_CHOICES = [
        ("TEXT", "Text"),
        ("IMAGE", "Image"),
        ("FILE", "File"),
    ]

    ticket = models.ForeignKey("Ticket", on_delete=models.CASCADE, related_name="chats")
    sender = models.ForeignKey(User, on_delete=models.CASCADE)

    message = models.TextField(blank=True, null=True)
    message_type = models.CharField(max_length=20, choices=MESSAGE_TYPE_CHOICES, default="TEXT")

    is_deleted = models.BooleanField(default=False)

    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.sender} -> {self.ticket}"

class TicketChatParticipant(models.Model):
    ROLE_CHOICES = [
        ("USER", "User"),
        ("AGENT", "Agent"),
        ("TL", "Team Lead"),
        ("MANAGER", "Manager"),
    ]

    ticket = models.ForeignKey("Ticket", on_delete=models.CASCADE, related_name="chat_participants")
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    role = models.CharField(max_length=20, choices=ROLE_CHOICES)

    joined_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        unique_together = ("ticket", "user")

    def __str__(self):
        return f"{self.user} - {self.ticket} ({self.role})"