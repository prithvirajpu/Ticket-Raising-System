from rest_framework import status
from django.db import transaction
from ..models import User
from core_app.models import AgentApplication,AgentCertificate
from core_app.constants import UserRole, ApprovalStatus
from rest_framework.pagination import PageNumberPagination

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

        if user:
            user.role = role
            user.approval_status = ApprovalStatus.APPROVED
            user.is_active = True
            user.is_verified = agent.email_verified
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
                password=agent.password
            )

        agent.status = ApprovalStatus.APPROVED
        agent.save()

    return {
        "data": {"message": f"Agent request approved as {role}."},
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

def update_client_profile_service(user, data):
    print('USER',user)
    print('authenticated',user.is_authenticated)
    company_name = data.get("company_name")
    business_type = data.get("business_type")
    phone = data.get("phone")

    if not company_name or not business_type or not phone:
        return {
            "data": None,
            "errors": {"details": "All fields are required"},
            "status": status.HTTP_400_BAD_REQUEST
        }

    user.name = company_name
    user.business_type = business_type
    user.phone = phone
    user.profile_completed = True
    user.save(update_fields=[
        "name",
        "business_type",
        "phone",
        "profile_completed"
    ])

    return {
        "data": {"message": "Profile updated successfully"},
        "errors": {},
        "status": status.HTTP_200_OK
    }

def update_agent_profile_service(user, data, files):

    agent_app = AgentApplication.objects.filter(email=user.email).first()

    if not agent_app:
        return {
            "data": None,
            "errors": {"details": "Agent application not found"},
            "status": status.HTTP_404_NOT_FOUND
        }

    phone = data.get("phone")
    skills = data.get("skills")
    resume = files.get("resume")

    if not phone or not skills:
        return {
            "data": None,
            "errors": {"details": "Phone and skills are required"},
            "status": status.HTTP_400_BAD_REQUEST
        }

    user.phone = phone
    user.profile_completed = True
    user.save(update_fields=[
        "phone",
        "profile_completed"
    ])
    agent_app.skills=skills
    agent_app.phone=phone
    if resume:
        agent_app.resume = resume
    agent_app.save(update_fields=["skills", "resume","phone"])
    certificates = files.getlist("certificates")
    AgentCertificate.objects.filter(agent=agent_app).delete()
    for cert in certificates:
        AgentCertificate.objects.create(
            agent=agent_app,
            file=cert
        )

    return {
        "data": {
            "message": "Profile completed successfully",
            "status": (agent_app.status or "PENDING").upper()
            
        },
        "errors": {},
        "status": status.HTTP_200_OK
    }

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