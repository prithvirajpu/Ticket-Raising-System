from rest_framework import status
from apps.tickets.models import (SLAPolicy,SubscriptionPlan)

from apps.tickets.serializer import SLAPolicySerializer

def fetch_sla_rules_service():
    rules= SLAPolicy.objects.select_related('plan').all().order_by('-id')
    serializer= SLAPolicySerializer(rules,many=True)

    return {
        'data':{'message':serializer.data},
        'errors':{},
        'status':status.HTTP_200_OK
    }

def create_sla_rule_service(request):
    plan_id= request.data.get('plan_id')
    priority= request.data.get('priority')
    if not plan_id or not priority:
        return {
            "data": {},
            "errors": {
                "details": "Plan and priority are required"
            },
            "status": status.HTTP_400_BAD_REQUEST
        }
    
    try:
        plan= SubscriptionPlan.objects.get(id=plan_id)
    except SubscriptionPlan.DoesNotExist:
        return {
            "data": {},
            "errors": {
                "details": "Subscription plan not found"
            },
            "status": status.HTTP_404_NOT_FOUND
        }
    
    existing_rule=SLAPolicy.objects.filter(plan=plan,priority=priority).exists()

    if existing_rule:

        return {
            "data": {},
            "errors": {
                "details": "Rule already exists for this priority"
            },
            "status": status.HTTP_400_BAD_REQUEST
        }
    rule = SLAPolicy.objects.create(
        plan=plan,
        priority=priority,
        resolution_time_minutes=request.data.get(
            'resolution_time_minutes'
        ),
        is_active=True
    )

    serializer = SLAPolicySerializer(rule)

    return {
        "data": {
            "message": "SLA Rule created successfully",
            "rule": serializer.data
        },
        "errors": {},
        "status": status.HTTP_201_CREATED
    }
    