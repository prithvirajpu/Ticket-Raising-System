from tickets.models import Ticket
from core_app.constants import UserRole
from rest_framework import status
from django.contrib.auth import get_user_model

User=get_user_model()

def dashboard_service(request,role):
    user= request.user

    if role==UserRole.ADMIN:
        return admin_dashboard(user)
    elif role== UserRole.TEAM_LEAD:
        return teamlead_dashboard(user)
    elif role== UserRole.AGENT:
        return agent_dashboard(user)
    elif role== UserRole.CLIENT:
        return client_dashboard(user)
    elif role== UserRole.USER:
        return user_dashboard(user)
    elif role== UserRole.MANAGER:
        return manager_dashboard(user)
    else:
        return {
            "data": None,
            "errors": {'details':"Invalid role"},
            "status": status.HTTP_400_BAD_REQUEST
        }
    
def admin_dashboard(user):
    pass

def teamlead_dashboard(user):
    # Team lead sees THEIR team agents' tickets
    team_agents = User.objects.filter(
        team_lead=user, 
        role=UserRole.TEAM_LEAD, 
    )
    
    assigned_tickets = Ticket.objects.filter(
        assigned_to__in=team_agents
    ).count()
    
    open_tickets = Ticket.objects.filter(
        assigned_to__in=team_agents,
        status='OPEN'
    ).count()
    
    return {
        'data': {
            'message': {
                'team_tickets': assigned_tickets,
                'open': open_tickets,
                'team_agents': team_agents.count(),
                'avg_completion': 85  # Or calculate
            }
        },
        'errors': {},
        'status': status.HTTP_200_OK
    }

def agent_dashboard(user):
    assigned_tickets= Ticket.objects.filter(assigned_to_id=user.id).count()
    open=Ticket.objects.filter(assigned_to_id=user.id,status='OPEN').count()
    in_progress=Ticket.objects.filter(assigned_to_id=user.id,status='IN_PROGRESS').count()
    return {
        'data':{'message':{
            'assigned_tickets':assigned_tickets,
            'open':open,
            'in_progress':in_progress
        }},
        'errors':{},
        'status':status.HTTP_200_OK
    }

def client_dashboard(user):
    pass

def manager_dashboard(user):
    pass

def user_dashboard(user):
    total_tickets= Ticket.objects.filter(created_by_id=user.id).count()
    escalated=Ticket.objects.filter(created_by_id=user.id,status='ESCALATED').count()
    in_progress=Ticket.objects.filter(created_by_id=user.id,status='IN_PROGRESS').count()
    resolved=Ticket.objects.filter(created_by_id=user.id,status='RESOLVED').count()
    return {
        'data':{'message':{
            'resolved':resolved,
            'total_tickets':total_tickets,
            'escalated':escalated,
            'in_progress':in_progress
        }},
        'errors':{},
        'status':status.HTTP_200_OK
    }
