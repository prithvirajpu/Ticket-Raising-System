from django.db import models
from django.contrib.auth import get_user_model
from tickets.models import Ticket

User=get_user_model()

class TicketAssignment(models.Model):
    STATUS_CHOICES = [
        ("PENDING", "Pending"),
        ("ACCEPTED", "Accepted"),
        ("REJECTED", "Rejected"),
    ]
    ticket=models.ForeignKey(Ticket,on_delete=models.CASCADE,related_name='assignments')
    agent=models.ForeignKey(User,on_delete=models.CASCADE)

    status=models.CharField(max_length=20,choices=STATUS_CHOICES,default='PENDING')
    rejection_reason=models.TextField(null=True,blank=True)
    created_at=models.DateTimeField(auto_now_add=True)
    expires_at=models.DateTimeField(null=True,blank=True)
    