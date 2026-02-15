from django.db import models
import random
from django.utils import timezone
from django.contrib.auth import get_user_model

User=get_user_model()

class EmailOTP(models.Model):
    email=models.EmailField(unique=True)
    otp=models.CharField(max_length=6)
    created_at=models.DateTimeField(auto_now_add=True)

    def is_expired(self):
        return timezone.now()>self.created_at+timezone.timedelta(minutes=1)

class AgentApplication(models.Model):
    STATUS_CHOICES=[
        ('PENDING','Pending'),
        ('APPROVED','Approved'),
        ('REJECTED','Rejected'),
    ]
    full_name=models.CharField(max_length=255)
    email=models.EmailField(unique=True)
    phone=models.CharField(max_length=20,default='0000000000')
    skills=models.TextField()
    resume=models.FileField(upload_to='resumes/')
    certificates=models.FileField(upload_to='certificates/',blank=True,null=True)
    password=models.CharField(max_length=255)
    status=models.CharField(max_length=20,choices=STATUS_CHOICES,default='PENDING')
    is_active=models.BooleanField(default=False)
    email_verified=models.BooleanField(default=False)
    applied_at=models.DateTimeField(auto_now_add=True)
    reviewed_at=models.DateTimeField(null=True,blank=True)

    def __str__(self):
        return self.full_name