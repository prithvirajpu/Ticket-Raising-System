from django.db import models 
import uuid
from django.core.validators import MinValueValidator, MaxValueValidator
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

    ISSUE_TYPES = (
    ('ORDER_ISSUE', 'Order Issue'),
    ('PAYMENT_ISSUE', 'Payment Issue'),
    ('REFUND_ISSUE', 'Refund Issue'),
    ('DELIVERY_ISSUE', 'Delivery Issue'),
    ('WALLET_ISSUE', 'Wallet Issue'),
    ('PRODUCT_ISSUE', 'Product Issue'),
    )

    STATUS_CHOICES=[
        ("OPEN","Open"),
        ("IN_PROGRESS","In Progress"),
        ("ESCALATED","Escalated"),
        ("RESOLVED","Resolved"),
        ("CLOSED","Closed"),
        ("REOPENED","Reopened"),
    ]

    ticket_code=models.CharField(max_length=30,unique=True,default=generate_ticket_code)
    client=models.ForeignKey('tickets.ClientProfile',on_delete=models.CASCADE,related_name='client_tickets')
    created_by=models.ForeignKey(User,on_delete=models.CASCADE,related_name='created_tickets')
    assigned_to=models.ForeignKey(User,on_delete=models.SET_NULL,
                                  null=True,blank=True,related_name='assigned_tickets' )

    issue_type=models.CharField(max_length=100,choices=ISSUE_TYPES,default='ORDER_ISSUE')
    priority=models.CharField(max_length=10,choices=PRIORITY_CHOICES,default='MEDIUM')
    status=models.CharField(max_length=20,choices=STATUS_CHOICES,default='OPEN')
    is_ai_generated = models.BooleanField(default=False)

    is_training_ticket = models.BooleanField(default=False)
    training_score = models.DecimalField(max_digits=4,decimal_places=2,null=True,blank=True)
    training_passed = models.BooleanField(default=False)
    training_feedback = models.TextField(blank=True,null=True)
    ai_customer_prompt = models.TextField(blank=True,null=True)

    subject=models.CharField(max_length=255)
    description=models.TextField()
    created_at=models.DateTimeField(auto_now_add=True)
    updated_at=models.DateTimeField(auto_now=True)

    def __str__(self):
        return self.ticket_code
    
class TicketReview(models.Model):
    ticket=models.OneToOneField(Ticket,on_delete=models.CASCADE)
    rating=models.PositiveIntegerField(
        validators=[MinValueValidator(1,message='Rating must be at least 1'),
                    MaxValueValidator(5,message='Rating must be at most 5'),]
    )
    review=models.TextField(blank=True)
    created_at=models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"Review for # {self.ticket.ticket_code} - {self.rating}/5"