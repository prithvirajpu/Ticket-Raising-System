from django.db import models
from django.contrib.auth import get_user_model
from apps.tickets.models import Ticket

User=get_user_model()

class TicketAssignment(models.Model):
    STATUS_CHOICES = [
        ("PENDING", "Pending"),
        ("ACCEPTED", "Accepted"),
        ("REJECTED", "Rejected"),
        ("CANCELLED", "Cancelled"),
        ("EXPIRED", "Expired"),
    ]
    ticket=models.ForeignKey(Ticket,on_delete=models.CASCADE,related_name='assignments')
    agent=models.ForeignKey(User,on_delete=models.CASCADE)
    status=models.CharField(max_length=20,choices=STATUS_CHOICES,default='PENDING')

    training_status = models.CharField(max_length=20,choices=[
            ("NOT_STARTED", "Not Started"),
            ("IN_PROGRESS", "In Progress"),
            ("RESOLVED", "Resolved"),
        ],
        default="NOT_STARTED")
    training_score = models.DecimalField(max_digits=4,decimal_places=2,null=True,blank=True)
    training_passed = models.BooleanField(null=True,blank=True)

    training_feedback = models.TextField(null=True,blank=True)
    created_at=models.DateTimeField(auto_now_add=True)
    expires_at=models.DateTimeField(null=True,blank=True)
    