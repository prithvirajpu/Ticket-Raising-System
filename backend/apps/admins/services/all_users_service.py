# services/admin_service.py

from apps.accounts.models import User
from django.db.models import Prefetch
from rest_framework import status


def get_all_users_service(request):

    users = User.objects.exclude(role__in=['ADMIN']).order_by("-created_at")

    data = []

    for u in users:
        data.append({
            "id": u.id,
            "email": u.email,
            "name": u.name,
            "role": u.role,
            "phone": u.phone,
            "is_active": u.is_active,

            # hierarchy
            "manager_id": u.manager.id if u.manager else None,
            "manager_email": u.manager.email if u.manager else None,

            "team_lead_id": u.team_lead.id if u.team_lead else None,
            "team_lead_email": u.team_lead.email if u.team_lead else None,
        })

    return {
        "data": {
            "users": data
        },
        "errors": None,
        "status": status.HTTP_200_OK
    }