from ...tickets.models import SubscriptionPlan,ClientProfile,ClientSubscription
from rest_framework import status
from datetime import timedelta
from django.utils import timezone

def plan_fetch_service(request):
    plans=SubscriptionPlan.objects.all().values(
            'id','name', 'price', 'duration_days', 'max_agents', 'max_tickets'
        )
    return {
        'data':{'message':list(plans)},
        'errors':{},
        'status':status.HTTP_200_OK
    }

def handle_demo_payment_service(request):
    plan_id= request.data.get('plan_id')

    if not plan_id:
        return {
            "data": {},
            "errors": {
                "details": "Plan id is required"
            },
            "status": status.HTTP_400_BAD_REQUEST
        }
    try:
        plan=SubscriptionPlan.objects.get(id=plan_id)
    except SubscriptionPlan.DoesNotExist:
        return{
            "data": {},
            "errors": {
                "details": "Plan not found"
            },
            "status": status.HTTP_404_NOT_FOUND
        }
  
    client = getattr(request.user, "client_profile", None)
    if not client:
        return {
            "data": {},
            "errors": {"details": "Client profile not found"},
            "status": status.HTTP_404_NOT_FOUND
        }
    

    start_date=timezone.now().date()
    end_date=start_date+ timedelta(days=plan.duration_days)
    subscription,created= ClientSubscription.objects.update_or_create(
        client=client,
        defaults={
            'plan':plan,
            'start_date':start_date,
            'end_date':end_date,
            'status':'ACTIVE'
        }
    )
    return {
        "data": {
            "message": f"{plan.name} activated successfully",
            "subscription_id": subscription.id,
            "plan": plan.name,
            "end_date": end_date
        },
        "errors": {},
        "status": status.HTTP_200_OK
    }