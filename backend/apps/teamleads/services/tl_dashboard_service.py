from django.core.cache import cache
from apps.accounts.models import User
from apps.tickets.models import Ticket
from rest_framework import status
from django.db.models import Q

def tl_dashboard_service(user):
    cache_key= f'tl_dashboard_{user.id}'
    cache_data=cache.get(cache_key)
    if cache_data:
        return cache_data
    
    agents=User.objects.filter(team_lead=user,role='AGENT',is_active=True)
    assigned_tickets=Ticket.objects.filter(Q(assigned_to__in=agents) |
                                           Q(assigned_to=user))
    
    open_tickets= assigned_tickets.filter(
        status__in=['OPEN','IN_PROGRESS','ESCALATED']
    ).count()
    
    resolved_tickets = assigned_tickets.filter(
        status__in=["RESOLVED","CLOSED",]
    ).count()

    result= {
        "data": {
            "message": {
                "total_agents": agents.count(),
                "assigned_tickets": assigned_tickets.count(),
                "open_tickets": open_tickets,
                "resolved_tickets": resolved_tickets,
            }
        },
        "errors": {},
        "status": status.HTTP_200_OK,
    }
    cache.set(cache_key,result,timeout=60)
    return result