from apps.clients.models import ClientProfile
from rest_framework import status
import logging 
logger= logging.getLogger(__name__)

def get_client_integration_keys(user):
    try:
        profile = ClientProfile.objects.get(user=user)
        logger.info("USER: %s", user.id, user.email)
        return {
            "data": {
                "company_name": profile.company_name,
                "internal_api_key": profile.internal_api_key,
                "sso_shared_secret": profile.sso_shared_secret,
            },
            "errors": {},
            "status": status.HTTP_200_OK
        }

    except Exception as e:
        import traceback
        traceback.print_exc()

        raise