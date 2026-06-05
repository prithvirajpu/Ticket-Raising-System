from rest_framework import status
from django.db import transaction
from django.contrib.auth import get_user_model
from apps.core_app.models import AgentApplication,AgentCertificate
from apps.core_app.constants import UserRole, ApprovalStatus
from rest_framework.pagination import PageNumberPagination

User=get_user_model()

def approve_user_service(user_id, role):

    if role not in [UserRole.AGENT, UserRole.MANAGER, UserRole.TEAM_LEAD]:
        return {
            "data": {},
            "errors": {"role": "Invalid role"},
            "status": status.HTTP_400_BAD_REQUEST
        }

    try:
        agent = AgentApplication.objects.get(
            id=user_id,
            status=ApprovalStatus.PENDING
        )

    except AgentApplication.DoesNotExist:
        return {
            "data": {},
            "errors": {"details": "Agent not found"},
            "status": status.HTTP_404_NOT_FOUND
        }

    with transaction.atomic():

        user = User.objects.filter(email=agent.email).first()

        # FETCH CLIENT PROFILE
        from ...tickets.models import ClientProfile
        client_profile = ClientProfile.objects.first()

        # FETCH TEAM LEAD FROM CLIENT PROFILE
        team_lead = None

        if client_profile:
            team_lead = client_profile.team_lead

        # FETCH MANAGER UNDER TEAM LEAD
        manager = None

        if team_lead:
            manager = User.objects.filter(
                role=UserRole.MANAGER,
                team_lead=team_lead
            ).first()

        if user:

            user.role = role
            user.approval_status = ApprovalStatus.APPROVED
            user.is_active = True
            user.is_verified = agent.email_verified

            # ROLE BASED ASSIGNMENTS

            if role == UserRole.AGENT:

                user.client = client_profile
                user.manager = manager
                user.team_lead = team_lead

            elif role == UserRole.TEAM_LEAD:

                user.client = client_profile
                user.manager = manager

            elif role == UserRole.MANAGER:

                user.client = client_profile

            user.save()

        else:

            user = User.objects.create(
                email=agent.email,
                name=agent.full_name,
                phone=agent.phone,
                role=role,
                approval_status=ApprovalStatus.APPROVED,
                is_active=True,
                is_verified=agent.email_verified,
                password=agent.password,

                client=client_profile,

                manager=manager if role == UserRole.AGENT else None,

                team_lead=team_lead if role == UserRole.AGENT else None,
            )

        agent.status = ApprovalStatus.APPROVED
        agent.save()

    return {
        "data": {
            "message": f"Agent request approved as {role}."
        },
        "errors": {},
        "status": status.HTTP_200_OK
    }

def reject_user_service(application_id):

    try:
        agent = AgentApplication.objects.get(
            id=application_id,
            status=ApprovalStatus.PENDING
        )
    except AgentApplication.DoesNotExist:
        return {
            "data": {},
            "errors": {"details": "Application not found"},
            "status": status.HTTP_404_NOT_FOUND
        }

    user = User.objects.filter(email=agent.email).first()

    with transaction.atomic():

        agent.status = ApprovalStatus.REJECTED
        agent.is_active = False
        agent.save(update_fields=["status", "is_active"])

        if user:
            user.approval_status = ApprovalStatus.REJECTED
            user.save(update_fields=["approval_status"])

    return {
        "data": {"message": "User rejected successfully"},
        "errors": {},
        "status": status.HTTP_200_OK
    }

def get_agent_application_detail_service(application_id):
    try:
        agent=AgentApplication.objects.get(id=application_id)
    except AgentApplication.DoesNotExist:
        return {
            "data": {},
            "errors": {"details": "Agent not found"},
            "status": status.HTTP_404_NOT_FOUND
        }
    data = {
        "id": agent.id,
        "full_name": agent.full_name,
        "email": agent.email,
        "phone": agent.phone,
        "skills": agent.skills,
        "status": agent.status,
        "resume": agent.resume.url if agent.resume else None,
        "certificates": [cert.file.url for cert in agent.certificates.all()],
        "created_at": agent.applied_at,
    }
    return {'data':data, 
            "errors":{},
            'status':status.HTTP_200_OK}

def get_client_list_service(request):
    try:
        clients = User.objects.filter(role=UserRole.CLIENT).order_by("-created_at")

        paginator = PageNumberPagination()
        paginator.page_size = 10
        page = paginator.paginate_queryset(clients, request) or []

        total_clients = clients.count()
        pending_clients = clients.filter(is_active=False).count()

        client_data = [{
            "id": client.id,
            "name": client.name,
            "email": client.email,
            "phone": client.phone,
            "business_type": client.business_type,
            "is_active": client.is_active,
            "date_joined": client.created_at
        } for client in page]

        return {
            "paginator": {
                "count": paginator.page.paginator.count,
                "next": paginator.get_next_link(),
                "previous": paginator.get_previous_link(),
                "page_size": paginator.page_size,
            },
            "data": {
                "results":{
                "total_clients": total_clients,
                "pending_clients": pending_clients,
                "clients": client_data
                }
            },
            "errors": None,
            "status": status.HTTP_200_OK
        }

    except Exception as e:
        return {
            "data": None,
            "errors": {"details": str(e)},
            "status": status.HTTP_500_INTERNAL_SERVER_ERROR
        }

def get_agent_list_service(request):
    try:
        agents = User.objects.filter(
            role__in=[UserRole.AGENT, UserRole.TEAM_LEAD, UserRole.MANAGER],
            approval_status=ApprovalStatus.APPROVED
        ).order_by("-created_at")

        paginator = PageNumberPagination()
        paginator.page_size = 10

        page = paginator.paginate_queryset(agents, request) 

        total_agents = agents.count()
        active_agents = agents.filter(is_active=True).count()
        inactive_agents = agents.filter(is_active=False).count()

        agent_data = [
            {
                "id": agent.id,
                "name": agent.name,
                "email": agent.email,
                "role": agent.role,
                "phone": agent.phone,
                "is_active": agent.is_active,
                "date_joined": agent.created_at,
            } for agent in page ]if page else []
        count=agents.count()
        next_link = paginator.get_next_link() if hasattr(paginator, "page") else None
        previous_link = paginator.get_previous_link() if hasattr(paginator, "page") else None

        return {
            "paginator": {
                "count": count,
                "next": next_link,
                "previous": previous_link,
                "page_size": paginator.page_size,
                },
            "data": {
                "results":{
                "total_agents": total_agents,
                "active_agents": active_agents,
                "inactive_agents": inactive_agents,
                "agents": agent_data
                }
            },
            "errors": None,
            "status": status.HTTP_200_OK
        }

    except Exception as e:
        return {
            "data": None,
            "errors": {"details": str(e)},
            "status": status.HTTP_500_INTERNAL_SERVER_ERROR
        }
    
def toggle_agent_status_service(agent_id,is_active):
    try:
        agent=User.objects.get(id=agent_id)
        agent.is_active=is_active
        agent.save(update_fields=['is_active'])
        if is_active is None:
            return {
                "data": None,
                "errors": {"details": "is_active is required"},
                "status": status.HTTP_400_BAD_REQUEST
            }
        return {
            'data':{
                'message':'Agent status updated successfully',
                "agent_id":agent.id,
                "is_active":agent.is_active
            },
            "errors":{},
            "status":status.HTTP_200_OK
        }
    except User.DoesNotExist:
        return {
            'data':None,
            'errors':{"details":'Agent not found'},
            'status':status.HTTP_404_NOT_FOUND
        }
    except Exception as e:
        return {
            'data':None,
            "errors":{'details':str(e)},
            "status":status.HTTP_500_INTERNAL_SERVER_ERROR
        }