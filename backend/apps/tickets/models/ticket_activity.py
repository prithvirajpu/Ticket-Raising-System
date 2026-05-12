from django.db import models
from django.contrib.auth import get_user_model
from apps.tickets.models import Ticket

User=get_user_model()
class TicketActivity(models.Model):
    ACTION_CHOICES = [
        ("CREATED", "Created"),
        ("ASSIGNED", "Assigned"),
        ("ACCEPTED", "Accepted"),
        ("AUTO_ASSIGNED", "Auto Assigned"),
        ("ESCALATED", "Escalated"),
        ("RESOLVED", "Resolved"),
        ("REOPENED", "Reopened"),
        ("CLOSED", "Closed"),
        ("TRANSFERRED", "Transferred"),
    ]
    ticket=models.ForeignKey(Ticket,on_delete=models.CASCADE,related_name='activities')
    action= models.CharField(max_length=50,choices=ACTION_CHOICES)
    performed_by= models.ForeignKey(User,models.SET_NULL,null=True,blank=True)
    description= models.TextField(blank=True)
    created_at= models.DateTimeField(auto_now_add=True)