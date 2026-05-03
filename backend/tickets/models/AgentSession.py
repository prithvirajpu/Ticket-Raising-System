from django.conf import settings
from django.db import models

class AgentSession(models.Model):
    user=models.ForeignKey(settings.AUTH_USER_MODEL,on_delete=models.CASCADE)
    start_time=models.DateTimeField(auto_now_add=True)
    last_active=models.DateTimeField(null=True,blank=True)
    total_active_seconds = models.IntegerField(default=0)
    is_active = models.BooleanField(default=True)

    def __str__(self):
        return f"{self.user} - {self.total_active_seconds}s"