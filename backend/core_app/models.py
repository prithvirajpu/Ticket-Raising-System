from django.db import models
import random
from django.utils import timezone
from django.contrib.auth import get_user_model

User=get_user_model()

class EmailOTP(models.Model):
    user=models.ForeignKey(User,on_delete=models.CASCADE)
    otp=models.CharField(max_length=6)
    created_at=models.DateTimeField(auto_now_add=True)

    def is_expired(self):
        return timezone.now()>self.created_at+timezone.timedelta(minutes=10)
    