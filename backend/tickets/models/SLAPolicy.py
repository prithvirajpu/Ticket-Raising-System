from django.db import models
from .SubscriptionPlan import SubscriptionPlan
from .ticket import Ticket

class SLAPolicy(models.Model):
    PRIORITY=[
        ("LOW", "Low"),
        ("MEDIUM", "Medium"),
        ("HIGH", "High"),
    ]
    plan=models.ForeignKey(SubscriptionPlan,on_delete=models.CASCADE,related_name='sla_policies')
    priority=models.CharField(max_length=20,choices=PRIORITY,default='MEDIUM')
    resolution_time_minutes=models.IntegerField()
    auto_reassign=models.BooleanField(default=True)
    max_reassign_attempts=models.IntegerField(default=3)
    is_active=models.BooleanField(default=True)

class TicketSLATracking(models.Model):
    SLA_TRACKS=[
        ("ON_TRACK", "On Track"),
        ("BREACHED", "Breached"),
        ("MET", "Met"),
    ]
    ticket=models.OneToOneField(Ticket,on_delete=models.CASCADE,related_name="sla_tracking")
    sla_policy=models.ForeignKey(SLAPolicy,on_delete=models.SET_NULL,null=True)

    sla_deadline=models.DateTimeField()
    first_response_at=models.DateTimeField(null=True,blank=True)
    resolved_at=models.DateTimeField(null=True,blank=True)
    sla_status=models.CharField(max_length=20,choices=SLA_TRACKS,default='ON_TRACK')

    breach_reason=models.TextField(null=True,blank=True)
    created_at=models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f'SLA Tracking for Ticket {self.ticket.id}'
