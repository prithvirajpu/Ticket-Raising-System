from django.db import models
from .profiles import ClientProfile

class SubscriptionPlan(models.Model):
    name=models.CharField(max_length=100)
    price=models.DecimalField(max_digits=10,decimal_places=2)
    duration_days=models.IntegerField()
    max_agents=models.IntegerField()
    max_tickets=models.IntegerField()

    created_at=models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.name
    
class ClientSubscription(models.Model):
    STATUS_FIELDS=[
        ("ACTIVE", "Active"),
        ("EXPIRED", "Expired"),
        ("CANCELLED", "Cancelled")
    ]
    client=models.ForeignKey(ClientProfile,on_delete=models.CASCADE,related_name="subscriptions")
    plan =models.ForeignKey(SubscriptionPlan,on_delete=models.CASCADE)

    start_date=models.DateField()
    end_date=models.DateField()
    status=models.CharField(max_length=20,choices=STATUS_FIELDS,default='ACTIVE') 
    created_at=models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f'{self.client} -{self.plan}'