import secrets
from rest_framework import status
from apps.clients.models import ClientProfile
from django.db import transaction


def regenerate_client_keys_service(user):
    try:
        with transaction.atomic():
            client_profile = ClientProfile.objects.filter(user=user).first()

            if not client_profile:
                return {
                    "data": None,
                    "errors": {"details": "Client profile not found"},
                    "status": status.HTTP_400_BAD_REQUEST
                }

            # 🔐 regenerate BOTH keys
            client_profile.internal_api_key = "trs_live_" + secrets.token_urlsafe(32)
            client_profile.sso_shared_secret = "trs_sso_" + secrets.token_urlsafe(32)

            client_profile.save()

            return {
                "data": {
                    "message": "Keys regenerated successfully",
                    "internal_api_key": client_profile.internal_api_key,
                    "sso_shared_secret": client_profile.sso_shared_secret,
                },
                "errors": {},
                "status": status.HTTP_200_OK
            }

    except Exception as e:
        return {
            "data": None,
            "errors": {"details": str(e)},
            "status": status.HTTP_500_INTERNAL_SERVER_ERROR
        }
    
def update_app_url_service(user, data):
    try:
        app_url = data.get("app_url")

        if not app_url:
            return {
                "data": None,
                "errors": {
                    "details": "app_url is required"
                },
                "status": status.HTTP_400_BAD_REQUEST
            }

        client = ClientProfile.objects.filter(
            user=user
        ).first()

        if not client:
            return {
                "data": None,
                "errors": {
                    "details": "Client not found"
                },
                "status": status.HTTP_404_NOT_FOUND
            }

        client.app_url = app_url
        client.save(update_fields=["app_url"])

        return {
            "data": {
                "message": "Application URL updated successfully.",
                "app_url": client.app_url
            },
            "errors": None,
            "status": status.HTTP_200_OK
        }

    except Exception as e:
        return {
            "data": None,
            "errors": {
                "details": str(e)
            },
            "status": status.HTTP_500_INTERNAL_SERVER_ERROR
        }