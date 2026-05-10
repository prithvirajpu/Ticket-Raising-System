from rest_framework import status
from django.db import transaction

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