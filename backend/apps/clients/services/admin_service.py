from rest_framework import status
from django.db import transaction
from apps.clients.models import ClientProfile

def update_client_profile_service(user, data):
    name = data.get("name")
    phone = data.get("phone")

    if not name or not phone:
        return {
            "data": None,
            "errors": {"details": "All fields are required"},
            "status": status.HTTP_400_BAD_REQUEST
        }

    with transaction.atomic():

        user.name = name
        user.phone = phone
        user.profile_completed = True
        user.save(update_fields=[
            "name",
            "phone",
            "profile_completed"
        ])

        client_profile, created = ClientProfile.objects.get_or_create(user=user)

        client_profile.company_name = name
        client_profile.save(update_fields=[
            "company_name",
        ])

    return {
        "data": {"message": "Profile updated successfully"},
        "errors": {},
        "status": status.HTTP_200_OK
    }