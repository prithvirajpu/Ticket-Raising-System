from rest_framework import status
from rest_framework_simplejwt.tokens import RefreshToken
from ..models import PasswordResetToken
from core_app.utils import generate_otp,send_otp_email,generate_jwt_token
from core_app.models import EmailOTP,AgentApplication
from core_app.constants import UserRole,ApprovalStatus
from datetime import timedelta
from django.utils import timezone
from django.conf import settings
from google.auth.transport import requests
from google.oauth2 import id_token as google_id_token
from django.contrib.auth import get_user_model

User=get_user_model()

def login_service(user):

    refresh = RefreshToken.for_user(user)

    return {
        "data": {
            "access": str(refresh.access_token),
            "refresh": str(refresh),
            "role": user.role
        },
        "errors": None,
        "status": status.HTTP_200_OK
    }

def reset_password_service(reset_token,new_password):
    token_obj=PasswordResetToken.objects.filter(token=reset_token).first()

    if not token_obj:
        return {
            "data": None,
            "errors": {"details": "Invalid reset token"},
            "status": status.HTTP_404_NOT_FOUND
        }
    
    if token_obj.is_expired():
        token_obj.delete()
        return {
            "data": None,
            "errors": {"details": "OTP expired"},
            "status": status.HTTP_400_BAD_REQUEST
        }
    user=token_obj.user
    if user.check_password(new_password):
        return {
            "data": None,
            "errors": {"details": "New password cannot be the same as the old password"},
            "status": status.HTTP_400_BAD_REQUEST
        }
    
    user.set_password(new_password)
    user.save()
    token_obj.delete()
    return {
        "data": {"message": "Password reset successful"},
        "errors": None,
        "status": status.HTTP_200_OK
    }

def forgot_password_service(email):
    user = User.objects.filter(email__iexact=email).first()
    if not user:
        return {
            "data": None,
            "errors": {"email": "User not found"},
            "status": status.HTTP_400_BAD_REQUEST
        }

    recent_otp = EmailOTP.objects.filter(
        email=email,
        purpose='RESET',
        created_at__gte=timezone.now() - timedelta(minutes=1)
    ).first()
    if recent_otp:
        expiry_time = recent_otp.created_at + timedelta(minutes=1)
    else:
        EmailOTP.objects.filter(
            email=email,
            purpose='RESET'
        ).delete()
        otp = generate_otp()
        EmailOTP.objects.create(
            email=email,
            otp=otp,
            purpose='RESET'
        )
        try:
            send_otp_email(email, otp)
        except Exception:
            pass
        expiry_time = timezone.now() + timedelta(minutes=1)
    return {
        "data": {
            "message": "OTP sent successfully",
            "expires_at": expiry_time.isoformat()
        },
        "errors": None,
        "status": status.HTTP_200_OK
    }

def google_client_auth_service(token,role=None):

    if not token:
        return {
            "data": None,
            "errors": {"details": "Missing token"},
            "status": status.HTTP_400_BAD_REQUEST
        }
    
    try:
        idinfo = google_id_token.verify_oauth2_token( token, requests.Request(), settings.GOOGLE_CLIENT_ID)
        email = idinfo.get("email")
        
        if not email:
            return {
                "data": None,
                "errors": {"details": "Unable to fetch email from Google"},
                "status": status.HTTP_400_BAD_REQUEST
            }
        
        user=User.objects.filter(email=email).first()

        if user and user.approval_status=='REJECTED':
            return {
                "data": None,
                "errors": {"details": "Agent application is rejected"},
                "status": status.HTTP_400_BAD_REQUEST
            }
        
        if not role:
            if not user:
                return {
                    "data": None,
                    "errors": {"details": "Account not found. Please sign up first"},
                    "status": status.HTTP_400_BAD_REQUEST
                }
        else:
            if role == UserRole.CLIENT:
                user, created = User.objects.get_or_create(
                    email=email,
                    defaults={"role": UserRole.CLIENT,"approval_status": ApprovalStatus.APPROVED,"profile_completed": False,"is_active": True,"is_verified": True,},)
            elif role == "AGENT":
                user, created = User.objects.get_or_create( email=email, defaults={ "role": UserRole.AGENT, "approval_status": "PENDING",
                                                        "profile_completed": False, "is_active": True, "is_verified": True,},)
                
                AgentApplication.objects.get_or_create(email=email,defaults={"status": ApprovalStatus.PENDING,"email_verified": True,},)
            else:
                return {
                    "data": None,
                    "errors": {"details": "Invalid role"},
                    "status": status.HTTP_400_BAD_REQUEST
                }
            
            if not created and user.role != role:
                return {
                    "data": None,
                    "errors": {"details": f"Account already exists as {user.role}"},
                    "status": status.HTTP_400_BAD_REQUEST
                }

        jwt_token = generate_jwt_token(user)
        return {
            "data": {
                "message": "Login successful",
                "user_id": user.id,
                "email": user.email,
                "role": user.role,
                "approval_status": user.approval_status,
                "profile_completed": user.profile_completed,
                "access": jwt_token["access"],
                "refresh": jwt_token["refresh"]
            },
            "errors": None,
            "status": status.HTTP_200_OK
        }
    except ValueError:
        return {
            "data": None,
            "errors": {"details": "Invalid Google token"},
            "status": status.HTTP_400_BAD_REQUEST
        }