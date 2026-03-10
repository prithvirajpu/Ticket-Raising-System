from django.db import models 
import uuid
from django.contrib.auth import get_user_model
User=get_user_model()

def generate_ticket_code():
    return f"TCKT-{uuid.uuid4().hex[:8].upper()}"

class Ticket(models.Model):
    PRIORITY_CHOICES= [
        ("LOW","Low"),
        ("MEDIUM","Medium"),
        ("HIGH","High"),
    ]

    STATUS_CHOICES=[
        ("OPEN","Open"),
        ("IN_PROGRESS","In Progress"),
        ("ESCALATED","Escalated"),
        ("RESOLVED","Resolved"),
        ("CLOSED","Closed"),
    ]

    ticket_code=models.CharField(max_length=30,unique=True,default=generate_ticket_code)
    client=models.ForeignKey(User,on_delete=models.CASCADE,related_name='client_tickets')
    created_by=models.ForeignKey(User,on_delete=models.CASCADE,related_name='created_tickets')
    assigned_to=models.ForeignKey(User,on_delete=models.SET_NULL,
                                  null=True,blank=True,related_name='assigned_tickets' )

    issue_type=models.CharField(max_length=100)
    priority=models.CharField(max_length=10,choices=PRIORITY_CHOICES,default='MEDIUM')
    status=models.CharField(max_length=20,choices=STATUS_CHOICES,default='OPEN')

    subject=models.CharField(max_length=255)
    description=models.TextField()
    created_at=models.DateTimeField(auto_now_add=True)
    updated_at=models.DateTimeField(auto_now=True)

    def __str__(self):
        return self.ticket_code
    
