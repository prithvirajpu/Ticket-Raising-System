import jwt
from rest_framework import status
from django.shortcuts import redirect
from django.contrib.auth import get_user_model
User=get_user_model()
from .auth_services import login_service
from datetime import datetime
import logging
logger=logging.getLogger(__name__)


def sso_login_service(request,token):
    try:
        unverified_payload = jwt.decode(
            token,
            options={"verify_signature": False}
        )
        app_name = unverified_payload.get("app_name", "Shopkickora")
        print("APP NAME:", app_name)
        if not app_name:
            return {
                "data": None,
                "errors": {
                    "details": "Missing app name."
                },
                "status": status.HTTP_400_BAD_REQUEST
            }

        from apps.clients.models import ClientProfile

        client_profile = ClientProfile.objects.filter(
            company_name__iexact=app_name
        ).first()
        if not client_profile:
            return{
                 "data": None,
                "errors": {"details": "Invalid client"},
                "status": status.HTTP_400_BAD_REQUEST
            }
        payload=jwt.decode(token,client_profile.sso_shared_secret,algorithms=['HS256'])
        email = payload.get("email")
        if not email:
            return {
                "data": None,
                "errors": {
                    "details": "Missing Email."
                },
                "status": status.HTTP_400_BAD_REQUEST
            }
        name = payload.get("username", "User")
        
        user=User.objects.filter(email=email).first()
        if user:
            if user.role !='USER':
                return redirect( "http://localhost:5173/sso-error?code=role_conflict")
        if not user:
            user = User.objects.create(
                email=email,
                name=name,
                role= "USER",
                profile_completed=payload.get(
                    "is_profile_completed",
                    True
                ),
                is_active=True,
                is_verified=True,
                approval_status='APPROVED'
            )
        from apps.users.models import ClientUser
        if client_profile:
            ClientUser.objects.get_or_create(
                user=user,
                client_profile=client_profile
            )
        print("CLIENTuser created or fetched")
        return login_service(user,client_profile)
    except jwt.ExpiredSignatureError as e:
        return {
            'data':None,
            'errors':{"details":'SSO token expired'},
            'status':status.HTTP_400_BAD_REQUEST
        }
    except jwt.InvalidTokenError:
        return{
            'data':None,
            'errors':{"details":'Invalid SSO token'},
            'status':status.HTTP_400_BAD_REQUEST
        }
    except Exception as e:
        logger.exception(e)
        return {
            'data':None,
            'errors':{"details":str(e)},
            'status':status.HTTP_500_INTERNAL_SERVER_ERROR
        }
