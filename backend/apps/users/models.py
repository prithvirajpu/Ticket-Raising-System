from django.db import models
from apps.clients.models import ClientProfile
from apps.accounts.models import User

# Create your models here.

class ClientUser(models.Model):
    user = models.OneToOneField( User, on_delete=models.CASCADE, related_name="client_user")
    client_profile = models.ForeignKey( ClientProfile, on_delete=models.CASCADE, related_name="users")
    external_user_id = models.CharField( max_length=255, blank=True, null=True)

    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.user.email} - {self.client_profile.company_name}"