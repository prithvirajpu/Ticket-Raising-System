from rest_framework import status
from django.core.cache import cache

from apps.accounts.models import User
from apps.tickets.models import Ticket
from django.db.models import Q

import logging
logger=logging.getLogger(__name__)

def manager_dashboard_service(user):
    cache_key= f'manager_dashboard_{user.id}'
    cached_data=cache.get(cache_key)
    
    if cached_data:
        return cached_data
    
    team_leads= User.objects.filter(manager=user,
                role='TEAM_LEAD',is_active=True)
    
    agents= User.objects.filter(team_lead__in=team_leads,
                            role='AGENT',is_active=True)
    
    tickets=Ticket.objects.filter(Q(assigned_to__in=agents) | 
                                    Q(assigned_to=user) | 
                                  Q (assigned_to__in=team_leads))
    
    resolved_tickets= tickets.filter(
        status__in=["RESOLVED","CLOSED"]).count()
    
    result= {
        "data": {
            "message": {
                "team_leads": team_leads.count(),
                "agents": agents.count(),
                "total_tickets": tickets.count(),
                "resolved_tickets": resolved_tickets,
            }
        },
        "errors": {},
        "status": status.HTTP_200_OK,
    }
    cache.set(cache_key,result,timeout=60)
    return result