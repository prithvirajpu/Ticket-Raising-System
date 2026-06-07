from rest_framework import status
from django.db import transaction
from django.contrib.auth import get_user_model
from apps.core_app.models import AgentApplication,AgentCertificate
from apps.core_app.constants import UserRole, ApprovalStatus
from rest_framework.pagination import PageNumberPagination

User=get_user_model()
def update_agent_profile_service(user, data, files):

    agent_app = AgentApplication.objects.filter(email=user.email).first()

    if not agent_app:
        return {
            "data": None,
            "errors": {"details": "Agent application not found"},
            "status": status.HTTP_404_NOT_FOUND
        }

    full_name=data.get('full_name')
    phone = data.get("phone")
    skills = data.get("skills")
    resume = files.get("resume")

    if not phone or not skills:
        return {
            "data": None,
            "errors": {"details": "Phone and skills are required"},
            "status": status.HTTP_400_BAD_REQUEST
        }
    user.name=full_name
    user.phone = phone
    user.profile_completed = True
    user.save(update_fields=[
        "phone",
        "profile_completed",
        "name"
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