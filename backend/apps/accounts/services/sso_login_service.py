import jwt
from rest_framework import status
from django.conf import settings
from django.shortcuts import redirect
from django.contrib.auth import get_user_model
User=get_user_model()
from .auth_services import login_service
from datetime import datetime


def sso_login_service(request,token):
    try:
        payload=jwt.decode(token,settings.SSO_SHARED_SECRET,algorithms=['HS256'])
        email=payload.get('email')
        app_name= payload.get('app_name','Shopkickora')
        name= payload.get('username','User')
        from apps.tickets.models import ClientProfile
        client_profile=None
        if app_name:
            client_profile = ClientProfile.objects.filter(
                company_name__iexact=app_name
            ).first()
        user=User.objects.filter(email=email).first()
        if user:
            if user.role !='USER':
                return redirect( "http://localhost:5173/sso-error?code=role_conflict")
        if not user:
            user = User.objects.create(
                email=email,
                name=name,
                role=payload.get("role", "USER"),
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
        return login_service(user)
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
        return {
            'data':None,
            'errors':{"details":str(e)},
            'status':status.HTTP_500_INTERNAL_SERVER_ERROR
        }
