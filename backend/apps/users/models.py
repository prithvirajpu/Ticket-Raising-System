from django.db import models
from apps.clients.models import ClientProfile
from apps.accounts.models import User

# Create your models here.

class ClientUser(models.Model):
    user = models.ForeignKey( User, on_delete=models.CASCADE, related_name="client_users")
    client_profile = models.ForeignKey( ClientProfile, on_delete=models.CASCADE, related_name="users")

    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=["user", "client_profile"],
                name="unique_user_client"
            )
        ]
    def __str__(self):
        return f"{self.user.email} - {self.client_profile.company_name}"