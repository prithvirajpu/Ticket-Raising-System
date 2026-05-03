from rest_framework import serializers
from tickets.models import Ticket,TicketAssignment,TicketSLATracking

class TicketSerializer(serializers.ModelSerializer):
    sla=serializers.SerializerMethodField()

    class Meta:
        model=Ticket
        fields=['id','ticket_code','subject','description','status','issue_type','priority','created_at','sla']

    def get_sla(self, obj):
        sla_tracking = TicketSLATracking.objects.filter(
            ticket_id=obj.id
        ).select_related('sla_policy').order_by('-created_at').first()
        
        if not sla_tracking:
            return None
            
        return {
            'sla_deadline': sla_tracking.sla_deadline.isoformat() if sla_tracking.sla_deadline else None,
            'sla_status': sla_tracking.sla_status,
            'first_response_at': sla_tracking.first_response_at.isoformat() if sla_tracking.first_response_at else None,
            'policy_resolution_minutes': sla_tracking.sla_policy.resolution_time_minutes if sla_tracking.sla_policy else None,
        }

class AgentTicketRequestSerializer(serializers.ModelSerializer):
    ticket_id = serializers.IntegerField(source="ticket.id")
    ticket_code = serializers.CharField(source="ticket.ticket_code")
    subject = serializers.CharField(source="ticket.subject")
    description = serializers.CharField(source="ticket.description")
    priority = serializers.CharField(source="ticket.priority")
    created_at = serializers.DateTimeField(source="ticket.created_at")

    class Meta:
        model=TicketAssignment
        fields=['ticket_id',"ticket_code","subject","description","priority","created_at","status",]