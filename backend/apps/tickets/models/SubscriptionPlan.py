from django.db import models
from .profiles import ClientProfile

class SubscriptionPlan(models.Model):
    name=models.CharField(max_length=100)
    price=models.DecimalField(max_digits=10,decimal_places=2)
    duration_days=models.IntegerField()
    max_agents=models.IntegerField()
    max_tickets=models.IntegerField()
    stripe_price_id=models.CharField(max_length=255,blank=True,null=True)
    created_at=models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.name
    
class ClientSubscription(models.Model):
    STATUS_FIELDS=[
        ("ACTIVE", "Active"),
        ("CANCEL_SCHEDULED", "Cancel_scheduled"),
        ("EXPIRED", "Expired"),
        ("CANCELLED", "Cancelled")
    ]
    client=models.ForeignKey('tickets.ClientProfile',on_delete=models.CASCADE,related_name="subscriptions")
    plan =models.ForeignKey('tickets.SubscriptionPlan',on_delete=models.CASCADE)

    stripe_subscription_id = models.CharField(max_length=255,null=True,blank=True,unique=True)
    cancel_at_period_end = models.BooleanField(default=False)

    start_date=models.DateField()
    end_date=models.DateField()
    status=models.CharField(max_length=20,choices=STATUS_FIELDS,default='ACTIVE') 
    created_at=models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f'{self.client} -{self.plan}'